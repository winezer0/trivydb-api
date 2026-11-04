package trivydbapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	trivydb "github.com/aquasecurity/trivy-db/pkg/db"
	dbtypes "github.com/aquasecurity/trivy-db/pkg/types"
	bolt "go.etcd.io/bbolt"
)

func TestUpdatePublishesValidatedDatabaseAndPersistsActiveVersion(t *testing.T) {
	dbDir := filepath.Join(t.TempDir(), "trivy", "db")
	if err := os.MkdirAll(dbDir, 0o700); err != nil {
		t.Fatal(err)
	}
	createTestDatabase(t, dbDir)
	if err := trivydb.Init(dbDir); err != nil {
		t.Fatal(err)
	}
	defer trivydb.Close()

	server := &Server{
		opts:        Options{DBDir: dbDir, DBRepository: "fixture"},
		activeDBDir: dbDir,
		download: func(_ context.Context, _, destination string) error {
			createTestDatabase(t, destination)
			return os.WriteFile(filepath.Join(destination, "metadata.json"), []byte(`{"Version":2}`), 0o600)
		},
	}
	if err := server.update(context.Background()); err != nil {
		t.Fatal(err)
	}
	if server.activeDBDir == dbDir {
		t.Fatal("active database directory did not switch")
	}
	if _, err := os.Stat(trivydb.Path(server.activeDBDir)); err != nil {
		t.Fatalf("new database is unavailable: %v", err)
	}
	if _, err := os.Stat(trivydb.Path(dbDir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy database was not removed after activation: %v", err)
	}
	version, err := readActiveVersion(dbDir)
	if err != nil {
		t.Fatal(err)
	}
	if version != filepath.Base(server.activeDBDir) {
		t.Fatalf("persisted active version = %q, want %q", version, filepath.Base(server.activeDBDir))
	}
}

func TestUpdateFailureKeepsActiveDatabase(t *testing.T) {
	dbDir := filepath.Join(t.TempDir(), "db")
	if err := os.MkdirAll(dbDir, 0o700); err != nil {
		t.Fatal(err)
	}
	createTestDatabase(t, dbDir)
	if err := trivydb.Init(dbDir); err != nil {
		t.Fatal(err)
	}
	defer trivydb.Close()

	server := &Server{
		opts:        Options{DBDir: dbDir, DBRepository: "fixture"},
		activeDBDir: dbDir,
		download:    func(context.Context, string, string) error { return errors.New("simulated pull failure") },
	}
	if err := server.update(context.Background()); err == nil {
		t.Fatal("expected update failure")
	}
	if server.activeDBDir != dbDir {
		t.Fatalf("active database changed after failed update: %q", server.activeDBDir)
	}
	if _, err := os.Stat(trivydb.Path(dbDir)); err != nil {
		t.Fatalf("previous database was lost: %v", err)
	}
}

func TestPruneOldVersionsKeepsOnlyActive(t *testing.T) {
	directory := t.TempDir()
	for _, version := range []string{"20261101", "20261102", "20261103"} {
		if err := os.Mkdir(filepath.Join(directory, version), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := pruneOldVersions(directory, "20261103"); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, entry := range entries {
		got = append(got, entry.Name())
	}
	if len(got) != 1 || got[0] != "20261103" {
		t.Fatalf("retained versions = %v, want only the active version", got)
	}
}

func TestDatabaseUpdateTransportUsesConfiguredProxy(t *testing.T) {
	for _, proxy := range []string{
		"http://127.0.0.1:7890",
		"https://proxy.example:8443",
		"socks5://127.0.0.1:1080",
		"socks5h://127.0.0.1:1080",
	} {
		t.Run(proxy, func(t *testing.T) {
			transport, err := databaseUpdateTransport(proxy)
			if err != nil {
				t.Fatalf("create transport: %v", err)
			}
			httpTransport, ok := transport.(*http.Transport)
			if !ok {
				t.Fatalf("transport type = %T, want *http.Transport", transport)
			}
			proxyURL, err := httpTransport.Proxy(httptest.NewRequest(http.MethodGet, "https://ghcr.io/v2/", nil))
			if err != nil {
				t.Fatalf("resolve proxy: %v", err)
			}
			if proxyURL == nil || !strings.HasPrefix(proxyURL.String(), proxy) {
				t.Fatalf("proxy URL = %v, want prefix %q", proxyURL, proxy)
			}
		})
	}
}

func createTestDatabase(t *testing.T, directory string) {
	t.Helper()
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	database, err := bolt.Open(trivydb.Path(directory), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestHandlerRequiresAPIKey(t *testing.T) {
	server := &Server{opts: Options{APIKey: "secret"}}
	for _, test := range []struct {
		name   string
		setKey func(*http.Request)
		want   int
	}{
		{name: "missing key", want: http.StatusUnauthorized},
		{name: "wrong key", setKey: func(r *http.Request) { r.Header.Set(apiKeyHeader, "wrong") }, want: http.StatusUnauthorized},
		{name: "api key header", setKey: func(r *http.Request) { r.Header.Set(apiKeyHeader, "secret") }, want: http.StatusBadRequest},
		{name: "bearer key", setKey: func(r *http.Request) { r.Header.Set("Authorization", "Bearer secret") }, want: http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, apiPath, nil)
			if test.setKey != nil {
				test.setKey(req)
			}
			rec := httptest.NewRecorder()
			server.Handler().ServeHTTP(rec, req)
			if rec.Code != test.want {
				t.Fatalf("status = %d, want %d", rec.Code, test.want)
			}
		})
	}
}

func TestMatchesIDMatchesAliasesCaseInsensitively(t *testing.T) {
	advisory := dbtypes.Advisory{VulnerabilityID: "GHSA-abcd-1234", VendorIDs: []string{"CVE-2025-1234"}}
	if !matchesID("cve-2025-1234", advisory) {
		t.Fatal("expected alias ID to match regardless of case")
	}
	if matchesID("CVE-2025-9999", advisory) {
		t.Fatal("unexpected identifier match")
	}
}

func TestAppendUnique(t *testing.T) {
	got := appendUnique([]string{"CVE-1"}, "CVE-1", "CVE-2")
	if len(got) != 2 || got[0] != "CVE-1" || got[1] != "CVE-2" {
		t.Fatalf("appendUnique() = %#v", got)
	}
}

func TestQueryDatabaseResolvesAliasFromLocalDB(t *testing.T) {
	dbDir := t.TempDir()
	if err := trivydb.Init(dbDir); err != nil {
		t.Fatal(err)
	}
	defer trivydb.Close()
	config := trivydb.Config{}
	err := config.Connection().Update(func(tx *bolt.Tx) error {
		if err := config.PutVulnerability(tx, "GHSA-abcd-1234", dbtypes.Vulnerability{
			Title:       "Example vulnerability",
			Description: "Example description",
			Severity:    "HIGH",
		}); err != nil {
			return err
		}
		return config.PutAdvisory(tx, []string{"npm::", "lodash"}, "GHSA-abcd-1234", dbtypes.Advisory{
			VendorIDs:          []string{"CVE-2025-1234"},
			VulnerableVersions: []string{"<4.17.21"},
			PatchedVersions:    []string{">=4.17.21"},
			FixedVersion:       "4.17.21",
		})
	})
	if err != nil {
		t.Fatal(err)
	}

	results, err := queryDatabase("CVE-2025-1234", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].ID != "GHSA-abcd-1234" || results[0].Description != "Example description" {
		t.Fatalf("unexpected alias lookup results: %+v", results)
	}
	if len(results[0].Advisories) != 1 || results[0].Advisories[0].FixedVersion != "4.17.21" {
		t.Fatalf("expected advisory version details: %+v", results[0].Advisories)
	}

	handler := (&Server{opts: Options{APIKey: "secret"}}).Handler()
	request := httptest.NewRequest(http.MethodGet, apiPath+"?id=CVE-2025-1234", nil)
	request.Header.Set(apiKeyHeader, "secret")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("HTTP query status = %d, want %d: %s", response.Code, http.StatusOK, response.Body.String())
	}
	var body struct {
		Code string `json:"code"`
		Msg  string `json:"msg"`
		Data struct {
			Results []result `json:"results"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode HTTP query response: %v", err)
	}
	if body.Code != "success" || body.Msg != "ok" || len(body.Data.Results) != 1 || body.Data.Results[0].ID != "GHSA-abcd-1234" {
		t.Fatalf("unexpected HTTP query response: %+v", body)
	}

	packageResults, err := queryDatabase("", "lodash", "4.17.20")
	if err != nil {
		t.Fatal(err)
	}
	if len(packageResults) != 1 || packageResults[0].QueryVersion != "4.17.20" || packageResults[0].Advisories[0].FixedVersion != "4.17.21" {
		t.Fatalf("unexpected package lookup results: %+v", packageResults)
	}
	fixedVersionResults, err := queryDatabase("", "lodash", "4.17.21")
	if err != nil {
		t.Fatal(err)
	}
	if len(fixedVersionResults) != 0 {
		t.Fatalf("fixed version should not be affected: %+v", fixedVersionResults)
	}
	purlResults, err := queryDatabaseFiltered("", "lodash", "4.17.20", "npm")
	if err != nil || len(purlResults) != 1 {
		t.Fatalf("PURL ecosystem query = %d results, err=%v", len(purlResults), err)
	}

	batchHandler := (&Server{opts: Options{APIKey: "secret"}}).Handler()
	batchBody := bytes.NewBufferString(`{"queries":[{"id":"CVE-2025-1234"},{"purl":"pkg:npm/lodash@4.17.20"}]}`)
	batchRequest := httptest.NewRequest(http.MethodPost, apiPath, batchBody)
	batchRequest.Header.Set("Authorization", "Bearer secret")
	batchResponse := httptest.NewRecorder()
	batchHandler.ServeHTTP(batchResponse, batchRequest)
	if batchResponse.Code != http.StatusOK {
		t.Fatalf("batch query status = %d, want %d: %s", batchResponse.Code, http.StatusOK, batchResponse.Body.String())
	}
	var batchBodyResult struct {
		Data struct {
			Results []BatchQueryResult `json:"results"`
		} `json:"data"`
	}
	if err := json.Unmarshal(batchResponse.Body.Bytes(), &batchBodyResult); err != nil {
		t.Fatal(err)
	}
	if len(batchBodyResult.Data.Results) != 2 || len(batchBodyResult.Data.Results[0].Results) != 1 || len(batchBodyResult.Data.Results[1].Results) != 1 {
		t.Fatalf("unexpected batch query results: %+v", batchBodyResult.Data.Results)
	}
	if filepath.Base(trivydb.Path(dbDir)) != "trivy.db" {
		t.Fatal("expected Trivy database file name")
	}
}

func TestConcurrencyLimitRejectsExcessRequests(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	done := make(chan struct{})
	handler := concurrencyLimit(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		entered <- struct{}{}
		<-release
		w.WriteHeader(http.StatusOK)
	}), make(chan struct{}, 1))

	first := httptest.NewRecorder()
	go func() {
		defer close(done)
		handler.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/", nil))
	}()
	<-entered
	second := httptest.NewRecorder()
	handler.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/", nil))
	if second.Code != http.StatusServiceUnavailable {
		t.Fatalf("saturated request status = %d, want %d", second.Code, http.StatusServiceUnavailable)
	}
	close(release)
	<-done
}
