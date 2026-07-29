package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// newTestClient starts an httptest.Server serving fixed querybatch/vulns
// responses and returns a Client pointed at it, plus the server for
// t.Cleanup-based shutdown.
func newTestClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return &Client{BaseURL: srv.URL}
}

func TestNewClientDefaults(t *testing.T) {
	c := NewClient()
	if got := c.baseURL(); got != DefaultBaseURL {
		t.Errorf("baseURL() = %q, want %q", got, DefaultBaseURL)
	}
	if got := c.batchSize(); got != DefaultBatchSize {
		t.Errorf("batchSize() = %d, want %d", got, DefaultBatchSize)
	}
	if got := c.vulnFetchConcurrency(); got != DefaultVulnFetchConcurrency {
		t.Errorf("vulnFetchConcurrency() = %d, want %d", got, DefaultVulnFetchConcurrency)
	}
	if c.httpClient() != http.DefaultClient {
		t.Error("httpClient() should default to http.DefaultClient")
	}
}

func TestQueryReturnsVulnerabilitiesPerPurl(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/querybatch":
			var req queryBatchRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decoding querybatch request: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			if len(req.Queries) != 2 {
				t.Errorf("got %d queries, want 2: %+v", len(req.Queries), req.Queries)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			resp := queryBatchResponse{Results: []queryResult{
				{Vulns: []queryVuln{{ID: "GHSA-aaaa-bbbb-cccc"}}},
				{Vulns: nil},
			}}
			_ = json.NewEncoder(w).Encode(resp)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/vulns/GHSA-aaaa-bbbb-cccc":
			_ = json.NewEncoder(w).Encode(vulnResponse{
				ID:      "GHSA-aaaa-bbbb-cccc",
				Aliases: []string{"CVE-2026-1234"},
				Summary: "example vulnerability",
			})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}

	c := newTestClient(t, handler)
	got, err := c.Query(context.Background(), []string{
		"pkg:golang/example.com/vulnerable@v1.0.0",
		"pkg:golang/example.com/safe@v2.0.0",
	})
	if err != nil {
		t.Fatalf("Query returned error: %v", err)
	}

	vulnerable := got["pkg:golang/example.com/vulnerable@v1.0.0"]
	if len(vulnerable) != 1 {
		t.Fatalf("got %d vulnerabilities for vulnerable purl, want 1: %+v", len(vulnerable), vulnerable)
	}
	if vulnerable[0].ID != "GHSA-aaaa-bbbb-cccc" {
		t.Errorf("ID = %q, want GHSA-aaaa-bbbb-cccc", vulnerable[0].ID)
	}
	if vulnerable[0].CVE() != "CVE-2026-1234" {
		t.Errorf("CVE() = %q, want CVE-2026-1234", vulnerable[0].CVE())
	}
	if vulnerable[0].Summary != "example vulnerability" {
		t.Errorf("Summary = %q", vulnerable[0].Summary)
	}

	// Query's contract (see its docstring) is that purls with zero
	// vulnerabilities are omitted from the result map entirely, not mapped
	// to an empty slice - so this must assert the key is absent, not just
	// that any present value would be empty.
	if safe, ok := got["pkg:golang/example.com/safe@v2.0.0"]; ok {
		t.Errorf("got an entry for safe purl with zero vulnerabilities, want the key to be absent: %+v", safe)
	}
}

// TestQueryDeduplicatesPurlsAndVulnIDs asserts two distinct kinds of
// deduplication: input purls are deduplicated before querying (so
// querybatch is only called once for two identical purls), and the set of
// vulnerability IDs to fetch via GET /v1/vulns/{id} is deduplicated across
// all purls' results before fetching (so a single ID is only ever fetched
// once, even if it's returned for the same purl twice). The latter does
// NOT mean the returned per-purl []Vulnerability itself is deduplicated:
// if querybatch legitimately lists the same ID twice for one purl, that
// purl's result still contains two entries.
func TestQueryDeduplicatesPurlsAndVulnIDs(t *testing.T) {
	var queryBatchCalls, vulnCalls int
	handler := func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/querybatch":
			queryBatchCalls++
			var req queryBatchRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decoding querybatch request: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			if len(req.Queries) != 1 {
				t.Errorf("got %d queries, want 1 (duplicates should be deduplicated before querying): %+v", len(req.Queries), req.Queries)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			resp := queryBatchResponse{Results: []queryResult{
				{Vulns: []queryVuln{{ID: "GHSA-shared"}, {ID: "GHSA-shared"}}},
			}}
			_ = json.NewEncoder(w).Encode(resp)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/vulns/GHSA-shared":
			vulnCalls++
			_ = json.NewEncoder(w).Encode(vulnResponse{ID: "GHSA-shared"})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}

	c := newTestClient(t, handler)
	purl := "pkg:golang/example.com/mod@v1.0.0"
	got, err := c.Query(context.Background(), []string{purl, purl, ""})
	if err != nil {
		t.Fatalf("Query returned error: %v", err)
	}

	if queryBatchCalls != 1 {
		t.Errorf("querybatch called %d times, want 1", queryBatchCalls)
	}
	if vulnCalls != 1 {
		t.Errorf("GET /v1/vulns/{id} called %d times, want 1 (fetching should be deduplicated across the unique vulnerability ID set, even though the same ID appears twice in this querybatch result)", vulnCalls)
	}
	if len(got[purl]) != 2 {
		t.Errorf("got %d vulnerabilities, want 2 (the querybatch result listed the same ID twice for this purl, so the returned per-purl list is not itself deduplicated, only the underlying fetch is)", len(got[purl]))
	}
}

func TestQueryEmptyInput(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request for empty input: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	})

	got, err := c.Query(context.Background(), nil)
	if err != nil {
		t.Fatalf("Query returned error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d results, want 0", len(got))
	}
}

func TestQueryChunksLargeBatches(t *testing.T) {
	var batches [][]int
	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/querybatch" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var req queryBatchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decoding querybatch request: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		batches = append(batches, []int{len(req.Queries)})
		resp := queryBatchResponse{Results: make([]queryResult, len(req.Queries))}
		_ = json.NewEncoder(w).Encode(resp)
	}

	srv := httptest.NewServer(http.HandlerFunc(handler))
	t.Cleanup(srv.Close)
	c := &Client{BaseURL: srv.URL, BatchSize: 2}

	purls := []string{
		"pkg:golang/a@v1", "pkg:golang/b@v1", "pkg:golang/c@v1", "pkg:golang/d@v1", "pkg:golang/e@v1",
	}
	if _, err := c.Query(context.Background(), purls); err != nil {
		t.Fatalf("Query returned error: %v", err)
	}

	if len(batches) != 3 {
		t.Fatalf("got %d batch requests, want 3 (5 purls at batch size 2): %+v", len(batches), batches)
	}
	if batches[0][0] != 2 || batches[1][0] != 2 || batches[2][0] != 1 {
		t.Errorf("batch sizes = %v, want [2 2 1]", batches)
	}
}

func TestQueryPropagatesHTTPErrors(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	})

	_, err := c.Query(context.Background(), []string{"pkg:golang/example.com/mod@v1.0.0"})
	if err == nil {
		t.Fatal("expected error for a 500 response, got nil")
	}
}

func TestQueryPropagatesResultCountMismatch(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/querybatch" {
			t.Errorf("unexpected request: %s", r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// Deliberately return fewer results than queries.
		_ = json.NewEncoder(w).Encode(queryBatchResponse{Results: nil})
	})

	_, err := c.Query(context.Background(), []string{"pkg:golang/example.com/mod@v1.0.0"})
	if err == nil {
		t.Fatal("expected error for a result-count mismatch, got nil")
	}
}

func TestVulnerabilityCVEFallsBackToID(t *testing.T) {
	v := Vulnerability{ID: "GHSA-no-cve", Aliases: []string{"GO-2024-1"}}
	if got := v.CVE(); got != "GHSA-no-cve" {
		t.Errorf("CVE() = %q, want GHSA-no-cve (no CVE-prefixed alias present)", got)
	}
}

// TestQueryHandlesTrailingSlashInBaseURL guards against a regression where
// naive string concatenation of BaseURL+path produced a malformed URL (a
// doubled slash) whenever --osv-base-url was passed with a trailing slash.
func TestQueryHandlesTrailingSlashInBaseURL(t *testing.T) {
	var gotPaths []string
	handler := func(w http.ResponseWriter, r *http.Request) {
		gotPaths = append(gotPaths, r.URL.Path)
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/querybatch":
			_ = json.NewEncoder(w).Encode(queryBatchResponse{Results: []queryResult{
				{Vulns: []queryVuln{{ID: "GHSA-x"}}},
			}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/vulns/GHSA-x":
			_ = json.NewEncoder(w).Encode(vulnResponse{ID: "GHSA-x"})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(handler))
	t.Cleanup(srv.Close)

	// Deliberately add a trailing slash, as a user might when copy-pasting
	// a --osv-base-url value.
	c := &Client{BaseURL: srv.URL + "/"}
	if _, err := c.Query(context.Background(), []string{"pkg:golang/example.com/mod@v1.0.0"}); err != nil {
		t.Fatalf("Query returned error: %v", err)
	}

	for _, p := range gotPaths {
		if strings.Contains(p, "//") {
			t.Errorf("request path %q contains a doubled slash from BaseURL+path concatenation", p)
		}
	}
}

// TestQueryPreservesBaseURLPathPrefix guards against a regression where
// url.JoinPath would drop an existing path component in BaseURL (e.g. a
// mirror served at "https://mirror.example/api/") in favor of the
// leading-slash path passed by doJSON's callers (e.g. "/v1/querybatch").
// url.JoinPath's underlying path.Join does not treat a later element's
// leading slash as "absolute" the way filepath.Join on some OSes might;
// every element is joined and cleaned as an ordinary path segment, so the
// "/api" prefix must survive in the request path below.
func TestQueryPreservesBaseURLPathPrefix(t *testing.T) {
	var gotPaths []string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		gotPaths = append(gotPaths, r.URL.Path)
		_ = json.NewEncoder(w).Encode(queryBatchResponse{Results: []queryResult{
			{Vulns: []queryVuln{{ID: "GHSA-x"}}},
		}})
	})
	mux.HandleFunc("/api/v1/vulns/GHSA-x", func(w http.ResponseWriter, _ *http.Request) {
		gotPaths = append(gotPaths, "/api/v1/vulns/GHSA-x")
		_ = json.NewEncoder(w).Encode(vulnResponse{ID: "GHSA-x"})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request outside the /api/ prefix: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := &Client{BaseURL: srv.URL + "/api/"}
	if _, err := c.Query(context.Background(), []string{"pkg:golang/example.com/mod@v1.0.0"}); err != nil {
		t.Fatalf("Query returned error: %v", err)
	}

	if len(gotPaths) != 2 {
		t.Fatalf("got %d requests under the /api/ prefix, want 2 (querybatch + vulns): %v", len(gotPaths), gotPaths)
	}
}

func TestFetchVulnerabilitiesPropagatesHTTPErrors(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			_ = json.NewEncoder(w).Encode(queryBatchResponse{Results: []queryResult{
				{Vulns: []queryVuln{{ID: "GHSA-missing"}}},
			}})
		case "/v1/vulns/GHSA-missing":
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprint(w, "not found")
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}

	c := newTestClient(t, handler)
	_, err := c.Query(context.Background(), []string{"pkg:golang/example.com/mod@v1.0.0"})
	if err == nil {
		t.Fatal("expected error when fetching vulnerability details fails, got nil")
	}
}

func TestFetchVulnerabilitiesEmptyIDs(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request for empty IDs: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	})

	got, err := c.fetchVulnerabilities(context.Background(), nil)
	if err != nil {
		t.Fatalf("fetchVulnerabilities returned error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d results, want 0", len(got))
	}
}

func TestFetchVulnerabilitiesRunsConcurrentlyWithinLimit(t *testing.T) {
	const (
		numIDs      = 20
		concurrency = 4
	)

	var (
		mu          sync.Mutex
		inFlight    int
		maxInFlight int
	)
	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/querybatch" {
			t.Errorf("fetchVulnerabilities test should not call querybatch")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")

		mu.Lock()
		inFlight++
		if inFlight > maxInFlight {
			maxInFlight = inFlight
		}
		mu.Unlock()

		time.Sleep(10 * time.Millisecond) // give concurrent requests a chance to overlap

		mu.Lock()
		inFlight--
		mu.Unlock()

		_ = json.NewEncoder(w).Encode(vulnResponse{ID: id})
	}

	srv := httptest.NewServer(http.HandlerFunc(handler))
	t.Cleanup(srv.Close)
	c := &Client{BaseURL: srv.URL, VulnFetchConcurrency: concurrency}

	ids := make([]string, numIDs)
	for i := range ids {
		ids[i] = fmt.Sprintf("GHSA-%d", i)
	}

	got, err := c.fetchVulnerabilities(context.Background(), ids)
	if err != nil {
		t.Fatalf("fetchVulnerabilities returned error: %v", err)
	}
	if len(got) != numIDs {
		t.Fatalf("got %d results, want %d", len(got), numIDs)
	}
	for _, id := range ids {
		if got[id].ID != id {
			t.Errorf("got[%q].ID = %q, want %q", id, got[id].ID, id)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if maxInFlight == 0 {
		t.Error("no requests were observed in flight (test setup issue)")
	}
	if maxInFlight < 2 {
		t.Errorf("observed at most %d concurrent request(s), want at least 2 (requests should overlap, not run fully serially)", maxInFlight)
	}
	if maxInFlight > concurrency {
		t.Errorf("observed %d concurrent requests, want at most %d", maxInFlight, concurrency)
	}
}

func TestFetchVulnerabilitiesCancelsRemainingOnFirstError(t *testing.T) {
	const numIDs = 10

	handler := func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
		if id == "GHSA-1" {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = fmt.Fprint(w, "boom")
			return
		}
		time.Sleep(20 * time.Millisecond)
		_ = json.NewEncoder(w).Encode(vulnResponse{ID: id})
	}

	srv := httptest.NewServer(http.HandlerFunc(handler))
	t.Cleanup(srv.Close)
	c := &Client{BaseURL: srv.URL, VulnFetchConcurrency: 2}

	ids := make([]string, numIDs)
	for i := range ids {
		ids[i] = fmt.Sprintf("GHSA-%d", i)
	}

	_, err := c.fetchVulnerabilities(context.Background(), ids)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
