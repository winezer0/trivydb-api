package trivydbapi

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	trivydb "github.com/aquasecurity/trivy-db/pkg/db"
	dbtypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	bolt "go.etcd.io/bbolt"

	"github.com/tanspec/trivydb-api/internal/httpresponse"
)

const (
	apiPath                 = "/api/v1/query"
	apiKeyHeader            = "X-API-Key"
	defaultDBRepository     = "ghcr.io/aquasecurity/trivy-db:2"
	dbLayerMediaType        = "application/vnd.aquasec.trivy.db.layer.v1.tar+gzip"
	activeVersionFile       = "current.json"
	databaseVersionsDirName = "versions"
)

// Options configures the standalone Trivy database API.
type Options struct {
	DBDir                 string
	APIKey                string
	DBRepository          string
	UpdateInterval        time.Duration
	MaxConcurrentRequests int
}

// Server serves vulnerability lookups from a local Trivy database.
type Server struct {
	opts        Options
	mu          sync.RWMutex
	updateMu    sync.Mutex
	activeDBDir string
	download    func(context.Context, string, string) error
}

// New creates a server and prepares the local database, downloading it when missing.
func New(ctx context.Context, opts Options) (*Server, error) {
	if strings.TrimSpace(opts.DBDir) == "" {
		return nil, errors.New("database directory is required")
	}
	if opts.DBRepository == "" {
		opts.DBRepository = defaultDBRepository
	}
	server := &Server{opts: opts, activeDBDir: opts.DBDir, download: downloadDatabase}
	if activeDir, err := resolveActiveDBDir(opts.DBDir); err != nil {
		return nil, fmt.Errorf("resolve active Trivy DB directory: %w", err)
	} else if activeDir != "" {
		server.activeDBDir = activeDir
	}
	if _, err := os.Stat(trivydb.Path(server.activeDBDir)); errors.Is(err, os.ErrNotExist) {
		if err := server.update(ctx); err != nil {
			return nil, fmt.Errorf("initial Trivy DB download: %w", err)
		}
		return server, nil
	} else if err != nil {
		return nil, fmt.Errorf("access Trivy DB: %w", err)
	}
	if err := trivydb.Init(server.activeDBDir); err != nil {
		return nil, fmt.Errorf("open Trivy DB: %w", err)
	}
	return server, nil
}

// UpdateDatabase downloads, validates, and activates a database without serving HTTP.
func UpdateDatabase(ctx context.Context, opts Options) error {
	if strings.TrimSpace(opts.DBDir) == "" {
		return errors.New("database directory is required")
	}
	if opts.DBRepository == "" {
		opts.DBRepository = defaultDBRepository
	}
	server := &Server{opts: opts, activeDBDir: opts.DBDir, download: downloadDatabase}
	activeDir, err := resolveActiveDBDir(opts.DBDir)
	if err != nil {
		return fmt.Errorf("resolve active Trivy DB directory: %w", err)
	}
	if activeDir != "" {
		server.activeDBDir = activeDir
	}
	if err := server.update(ctx); err != nil {
		_ = trivydb.Close()
		return err
	}
	return trivydb.Close()
}

// Close closes the shared Trivy database handle.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return trivydb.Close()
}

// Handler returns the authenticated lookup API handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+apiPath, s.lookup)
	mux.HandleFunc("POST "+apiPath, s.batchLookup)
	mux.HandleFunc("POST /api/v1/admin/update", s.updateHandler)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		httpresponse.WriteSuccess(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	if s.opts.MaxConcurrentRequests <= 0 {
		return mux
	}
	semaphore := make(chan struct{}, s.opts.MaxConcurrentRequests)
	return concurrencyLimit(mux, semaphore)
}

// StartUpdater runs periodic updates when an interval is configured.
func (s *Server) StartUpdater(ctx context.Context) {
	if s.opts.UpdateInterval <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(s.opts.UpdateInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := s.update(ctx); err != nil {
					slog.Error("Trivy DB update failed", "error", err)
				}
			}
		}
	}()
}

func (s *Server) updateHandler(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		httpresponse.WriteError(w, http.StatusUnauthorized, "unauthorized", "valid API key required")
		return
	}
	if err := s.update(r.Context()); err != nil {
		httpresponse.WriteError(w, http.StatusBadGateway, "database_update_failed", "Trivy DB update failed")
		return
	}
	httpresponse.WriteSuccess(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (s *Server) update(ctx context.Context) error {
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	slog.Info("Downloading Trivy DB", "repository", s.opts.DBRepository)

	if err := os.MkdirAll(s.opts.DBDir, 0o700); err != nil {
		return fmt.Errorf("create Trivy DB root directory: %w", err)
	}
	versionsDir := filepath.Join(s.opts.DBDir, databaseVersionsDirName)
	if err := os.MkdirAll(versionsDir, 0o700); err != nil {
		return fmt.Errorf("create Trivy DB versions directory: %w", err)
	}
	stageDir, err := os.MkdirTemp(s.opts.DBDir, ".trivydb-staging-")
	if err != nil {
		return fmt.Errorf("create Trivy DB staging directory: %w", err)
	}
	defer os.RemoveAll(stageDir)
	if err := s.download(ctx, s.opts.DBRepository, stageDir); err != nil {
		return err
	}
	if err := validateDatabase(stageDir); err != nil {
		return fmt.Errorf("validate downloaded Trivy DB: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	version := time.Now().UTC().Format("20060102T150405.000000000")
	versionDir := filepath.Join(versionsDir, version)
	if err := os.Rename(stageDir, versionDir); err != nil {
		return fmt.Errorf("publish downloaded Trivy DB version: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	previousDir := s.activeDBDir
	if err := trivydb.Close(); err != nil {
		return fmt.Errorf("close active Trivy DB: %w", err)
	}
	if err := trivydb.Init(versionDir); err != nil {
		_ = reopenDatabase(previousDir)
		return fmt.Errorf("open downloaded Trivy DB: %w", err)
	}
	if err := writeActiveVersion(s.opts.DBDir, version); err != nil {
		_ = trivydb.Close()
		_ = reopenDatabase(previousDir)
		return fmt.Errorf("persist active Trivy DB version: %w", err)
	}
	s.activeDBDir = versionDir
	slog.Info("Activated Trivy DB version", "version", version)
	if err := removeLegacyDatabase(previousDir, s.opts.DBDir); err != nil {
		slog.Warn("Trivy DB legacy-version cleanup failed", "error", err)
	}
	if err := pruneOldVersions(versionsDir, version); err != nil {
		slog.Warn("Trivy DB old-version cleanup failed", "error", err)
	}
	return nil
}

func removeLegacyDatabase(previousDir, dbDir string) error {
	previousDir = filepath.Clean(previousDir)
	dbDir = filepath.Clean(dbDir)
	versionsDir := filepath.Join(dbDir, databaseVersionsDirName)
	if previousDir != dbDir && previousDir != versionsDir {
		return nil
	}
	for _, file := range []string{trivydb.Path(previousDir), filepath.Join(previousDir, "metadata.json")} {
		if err := os.Remove(file); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove legacy database file %q: %w", file, err)
		}
	}
	return nil
}

func pruneOldVersions(directory, active string) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	keep := map[string]struct{}{active: {}}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, preserve := keep[entry.Name()]; preserve {
			continue
		}
		if err := os.RemoveAll(filepath.Join(directory, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}

type activeVersion struct {
	Version string `json:"version"`
}

func versionsRoot(dbDir string) string { return dbDir }

func versionPath(dbDir, version string) string {
	return filepath.Join(versionsRoot(dbDir), databaseVersionsDirName, version)
}

func readActiveVersion(dbDir string) (string, error) {
	data, err := os.ReadFile(filepath.Join(versionsRoot(dbDir), activeVersionFile))
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	var active activeVersion
	if err := json.Unmarshal(data, &active); err != nil {
		return "", err
	}
	if active.Version == "" || active.Version == "." || active.Version == ".." || filepath.Base(active.Version) != active.Version {
		return "", errors.New("invalid active Trivy DB version")
	}
	if _, err := os.Stat(trivydb.Path(versionPath(dbDir, active.Version))); err != nil {
		return "", fmt.Errorf("active Trivy DB version is unavailable: %w", err)
	}
	return active.Version, nil
}

func resolveActiveDBDir(dbDir string) (string, error) {
	version, err := readActiveVersion(dbDir)
	if err != nil {
		return "", err
	}
	if version != "" {
		return versionPath(dbDir, version), nil
	}
	if _, err := os.Stat(trivydb.Path(dbDir)); err == nil {
		return dbDir, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	versionsDir := filepath.Join(dbDir, databaseVersionsDirName)
	if _, err := os.Stat(trivydb.Path(versionsDir)); err == nil {
		return versionsDir, nil
	}
	entries, err := os.ReadDir(versionsDir)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	for i := len(entries) - 1; i >= 0; i-- {
		if !entries[i].IsDir() {
			continue
		}
		candidate := filepath.Join(versionsDir, entries[i].Name())
		if _, err := os.Stat(trivydb.Path(candidate)); err == nil {
			return candidate, nil
		}
	}
	return "", nil
}

func reopenDatabase(directory string) error {
	if directory == "" {
		return nil
	}
	if _, err := os.Stat(trivydb.Path(directory)); err != nil {
		return err
	}
	return trivydb.Init(directory)
}

func writeActiveVersion(dbDir, version string) error {
	root := versionsRoot(dbDir)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(activeVersion{Version: version})
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(root, ".current-*")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return replaceFile(temporary.Name(), filepath.Join(root, activeVersionFile))
}

func downloadDatabase(ctx context.Context, repository, destination string) error {
	reference, err := name.ParseReference(repository)
	if err != nil {
		return fmt.Errorf("parse Trivy DB repository: %w", err)
	}
	descriptor, err := remote.Get(reference, remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return fmt.Errorf("download Trivy DB artifact: %w", err)
	}
	image, err := descriptor.Image()
	if err != nil {
		return fmt.Errorf("read Trivy DB artifact image: %w", err)
	}
	manifest, err := image.Manifest()
	if err != nil {
		return fmt.Errorf("read Trivy DB artifact manifest: %w", err)
	}
	for _, layerDescriptor := range manifest.Layers {
		if layerDescriptor.MediaType != dbLayerMediaType {
			continue
		}
		layer, err := image.LayerByDigest(layerDescriptor.Digest)
		if err != nil {
			return fmt.Errorf("read Trivy DB artifact layer: %w", err)
		}
		compressed, err := layer.Compressed()
		if err != nil {
			return fmt.Errorf("read compressed Trivy DB layer: %w", err)
		}
		defer compressed.Close()
		if err := extractDatabaseLayer(compressed, destination); err != nil {
			return fmt.Errorf("extract Trivy DB layer: %w", err)
		}
		return nil
	}
	return fmt.Errorf("Trivy DB artifact does not contain layer %q", dbLayerMediaType)
}

func extractDatabaseLayer(source io.Reader, destination string) error {
	gz, err := gzip.NewReader(source)
	if err != nil {
		return fmt.Errorf("open gzip layer: %w", err)
	}
	defer gz.Close()
	archive := tar.NewReader(gz)
	seen := map[string]bool{}
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		name := path.Clean(strings.TrimPrefix(header.Name, "./"))
		if header.Typeflag == tar.TypeDir {
			continue
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			return fmt.Errorf("unsupported archive entry %q", header.Name)
		}
		if name != "trivy.db" && name != "metadata.json" {
			return fmt.Errorf("unexpected archive entry %q", header.Name)
		}
		if seen[name] {
			return fmt.Errorf("duplicate archive entry %q", name)
		}
		seen[name] = true
		file, err := os.OpenFile(filepath.Join(destination, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		_, copyErr := io.CopyN(file, archive, header.Size)
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	if !seen["trivy.db"] || !seen["metadata.json"] {
		return errors.New("archive must contain trivy.db and metadata.json")
	}
	return nil
}

func validateDatabase(directory string) error {
	var metadata struct {
		Version int `json:"Version"`
	}
	data, err := os.ReadFile(filepath.Join(directory, "metadata.json"))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &metadata); err != nil {
		return fmt.Errorf("parse metadata.json: %w", err)
	}
	if metadata.Version != trivydb.SchemaVersion {
		return fmt.Errorf("unsupported schema version %d", metadata.Version)
	}
	database, err := bolt.Open(filepath.Join(directory, "trivy.db"), 0o400, &bolt.Options{ReadOnly: true, Timeout: 2 * time.Second})
	if err != nil {
		return fmt.Errorf("open trivy.db: %w", err)
	}
	return database.Close()
}

func (s *Server) lookup(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		httpresponse.WriteError(w, http.StatusUnauthorized, "unauthorized", "valid API key required")
		return
	}
	query := Query{ID: r.URL.Query().Get("id"), CVE: r.URL.Query().Get("cve"), Package: r.URL.Query().Get("package"), Version: r.URL.Query().Get("version"), PURL: r.URL.Query().Get("purl")}
	results, err := s.runQuery(query)
	if err != nil {
		writeQueryError(w, err)
		return
	}
	httpresponse.WriteSuccess(w, http.StatusOK, map[string]any{"results": results})
}

func (s *Server) batchLookup(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		httpresponse.WriteError(w, http.StatusUnauthorized, "unauthorized", "valid API key required")
		return
	}
	request, err := decodeBatchRequest(w, r)
	if err != nil {
		httpresponse.WriteError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	for i := range request.Queries {
		query, err := normalizeQuery(request.Queries[i])
		if err != nil {
			httpresponse.WriteError(w, http.StatusBadRequest, "invalid_query", fmt.Sprintf("queries[%d]: %v", i, err))
			return
		}
		request.Queries[i] = query
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	results := make([]BatchQueryResult, 0, len(request.Queries))
	for _, query := range request.Queries {
		items, err := runDatabaseQuery(query)
		if err != nil {
			httpresponse.WriteError(w, http.StatusInternalServerError, "database_lookup_failed", "Trivy DB lookup failed")
			return
		}
		results = append(results, BatchQueryResult{Query: query, Results: items})
	}
	httpresponse.WriteSuccess(w, http.StatusOK, map[string]any{"results": results})
}

type result struct {
	ID           string                                           `json:"id"`
	PackageName  string                                           `json:"package_name,omitempty"`
	QueryVersion string                                           `json:"query_version,omitempty"`
	Aliases      []string                                         `json:"aliases,omitempty"`
	Title        string                                           `json:"title,omitempty"`
	Description  string                                           `json:"description,omitempty"`
	Severity     string                                           `json:"severity,omitempty"`
	CVSS         map[dbtypes.SourceID]dbtypes.CVSS                `json:"cvss,omitempty"`
	Details      map[dbtypes.SourceID]dbtypes.VulnerabilityDetail `json:"details,omitempty"`
	Advisories   []dbtypes.Advisory                               `json:"advisories,omitempty"`
}

func queryDatabase(identifier, packageName, version string) ([]result, error) {
	return queryDatabaseFiltered(identifier, packageName, version, "")
}

func queryDatabaseFiltered(identifier, packageName, version, ecosystem string) ([]result, error) {
	db := trivydb.Config{}
	byID := map[string]*result{}
	if identifier != "" && packageName == "" {
		id := strings.ToUpper(identifier)
		vulnerability, err := db.GetVulnerability(id)
		if err == nil {
			byID[id] = &result{ID: id, Title: vulnerability.Title, Description: vulnerability.Description, Severity: vulnerability.Severity, CVSS: vulnerability.CVSS}
			byID[id].Details, _ = db.GetVulnerabilityDetail(id)
		}
		aliases, err := findAliasAdvisories(id)
		if err != nil {
			return nil, err
		}
		for vulnID, advisories := range aliases {
			entry := byID[vulnID]
			if entry == nil {
				vulnerability, _ := db.GetVulnerability(vulnID)
				entry = &result{ID: vulnID, Title: vulnerability.Title, Description: vulnerability.Description, Severity: vulnerability.Severity, CVSS: vulnerability.CVSS}
				entry.Details, _ = db.GetVulnerabilityDetail(vulnID)
				byID[vulnID] = entry
			}
			entry.Advisories = append(entry.Advisories, advisories...)
			for _, advisory := range advisories {
				entry.Aliases = appendUnique(entry.Aliases, advisory.VendorIDs...)
			}
		}
	}
	if packageName != "" {
		conn := db.Connection()
		var roots []string
		if err := conn.View(func(tx *bolt.Tx) error {
			return tx.ForEach(func(name []byte, bucket *bolt.Bucket) error {
				if bucket != nil {
					roots = append(roots, string(name))
				}
				return nil
			})
		}); err != nil {
			return nil, err
		}
		sort.Strings(roots)
		for _, source := range roots {
			if ecosystem != "" && !sourceMatchesPURLType(source, ecosystem) {
				continue
			}
			values, err := db.ForEachAdvisory([]string{source}, packageName)
			if err != nil {
				return nil, err
			}
			for vulnID, value := range values {
				var advisory dbtypes.Advisory
				if err := json.Unmarshal(value.Content, &advisory); err != nil {
					return nil, err
				}
				advisory.VulnerabilityID = vulnID
				if value.Source.ID != "" {
					advisory.DataSource = &dbtypes.DataSource{ID: value.Source.ID, Name: value.Source.Name, URL: value.Source.URL, BaseID: value.Source.BaseID}
				}
				if identifier != "" && !matchesID(identifier, advisory) {
					continue
				}
				if version != "" && !advisoryAffectsVersion(source, version, advisory) {
					continue
				}
				entry := byID[vulnID]
				if entry == nil {
					vulnerability, _ := db.GetVulnerability(vulnID)
					entry = &result{ID: vulnID, PackageName: packageName, QueryVersion: version, Title: vulnerability.Title, Description: vulnerability.Description, Severity: vulnerability.Severity, CVSS: vulnerability.CVSS}
					entry.Details, _ = db.GetVulnerabilityDetail(vulnID)
					byID[vulnID] = entry
				}
				if entry.PackageName == "" {
					entry.PackageName = packageName
				}
				if entry.QueryVersion == "" {
					entry.QueryVersion = version
				}
				entry.Aliases = appendUnique(entry.Aliases, advisory.VendorIDs...)
				entry.Advisories = append(entry.Advisories, advisory)
			}
		}
	}
	results := make([]result, 0, len(byID))
	for _, item := range byID {
		results = append(results, *item)
	}
	sort.Slice(results, func(i, j int) bool { return results[i].ID < results[j].ID })
	return results, nil
}

func (s *Server) authorized(r *http.Request) bool {
	if strings.TrimSpace(s.opts.APIKey) == "" {
		return true
	}
	key := strings.TrimSpace(r.Header.Get(apiKeyHeader))
	if key == "" {
		if value := r.Header.Get("Authorization"); strings.HasPrefix(strings.ToLower(value), "bearer ") {
			key = strings.TrimSpace(value[len("Bearer "):])
		}
	}
	return key != "" && len(key) == len(s.opts.APIKey) && subtle.ConstantTimeCompare([]byte(key), []byte(s.opts.APIKey)) == 1
}
