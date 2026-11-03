package trivydbapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/package-url/packageurl-go"
	"github.com/tanspec/trivydb-api/internal/httpresponse"
)

const (
	maxBatchQueries = 100
	maxBatchBody    = 1 << 20
)

type Query struct {
	ID        string `json:"id,omitempty"`
	CVE       string `json:"cve,omitempty"`
	Package   string `json:"package,omitempty"`
	Version   string `json:"version,omitempty"`
	PURL      string `json:"purl,omitempty"`
	ecosystem string
}

type BatchQueryRequest struct {
	Queries []Query `json:"queries"`
}

type BatchQueryResult struct {
	Query   Query    `json:"query"`
	Results []result `json:"results"`
}

type invalidQueryError struct{ message string }

func (e invalidQueryError) Error() string { return e.message }

func normalizeQuery(query Query) (Query, error) {
	query.ID = strings.TrimSpace(query.ID)
	query.CVE = strings.TrimSpace(query.CVE)
	if query.ID == "" {
		query.ID = query.CVE
	}
	query.CVE = ""
	query.Package = strings.TrimSpace(query.Package)
	query.Version = strings.TrimSpace(query.Version)
	query.PURL = strings.TrimSpace(query.PURL)
	query.ecosystem = ""
	if query.PURL != "" {
		parsed, err := packageurl.FromString(query.PURL)
		if err != nil {
			return Query{}, invalidQueryError{"purl is invalid"}
		}
		purlPackage := parsed.Name
		if parsed.Namespace != "" {
			purlPackage = parsed.Namespace + "/" + parsed.Name
		}
		if query.Package != "" && query.Package != purlPackage {
			return Query{}, invalidQueryError{"package does not match purl"}
		}
		if query.Version != "" && parsed.Version != "" && query.Version != parsed.Version {
			return Query{}, invalidQueryError{"version does not match purl"}
		}
		query.Package = purlPackage
		if query.Version == "" {
			query.Version = parsed.Version
		}
		query.ecosystem = strings.ToLower(parsed.Type)
	}
	if query.ID == "" && query.Package == "" {
		return Query{}, invalidQueryError{"id, package, or purl is required"}
	}
	if query.Version != "" && query.Package == "" {
		return Query{}, invalidQueryError{"version requires package or purl"}
	}
	return query, nil
}

func (s *Server) runQuery(query Query) ([]result, error) {
	query, err := normalizeQuery(query)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return runDatabaseQuery(query)
}

func runDatabaseQuery(query Query) ([]result, error) {
	return queryDatabaseFiltered(query.ID, query.Package, query.Version, query.ecosystem)
}

func decodeBatchRequest(w http.ResponseWriter, r *http.Request) (BatchQueryRequest, error) {
	defer r.Body.Close()
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBatchBody))
	decoder.DisallowUnknownFields()
	var request BatchQueryRequest
	if err := decoder.Decode(&request); err != nil {
		return BatchQueryRequest{}, fmt.Errorf("decode request body: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return BatchQueryRequest{}, errors.New("request body must contain a single JSON object")
	}
	if len(request.Queries) == 0 || len(request.Queries) > maxBatchQueries {
		return BatchQueryRequest{}, fmt.Errorf("queries must contain between 1 and %d items", maxBatchQueries)
	}
	return request, nil
}

func writeQueryError(w http.ResponseWriter, err error) {
	var invalid invalidQueryError
	if errors.As(err, &invalid) {
		httpresponse.WriteError(w, http.StatusBadRequest, "invalid_query", invalid.Error())
		return
	}
	httpresponse.WriteError(w, http.StatusInternalServerError, "database_lookup_failed", "Trivy DB lookup failed")
}

func concurrencyLimit(next http.Handler, semaphore chan struct{}) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case semaphore <- struct{}{}:
			defer func() { <-semaphore }()
			next.ServeHTTP(w, r)
		default:
			httpresponse.WriteError(w, http.StatusServiceUnavailable, "server_busy", "maximum concurrent requests reached")
		}
	})
}
