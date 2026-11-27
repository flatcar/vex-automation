package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"osv.dev/bindings/go/osvdev"
)

// newTestClient starts an httptest.Server serving fixed querybatch/vulns
// responses and returns a Client pointed at it, plus the server for
// t.Cleanup-based shutdown.
func newTestClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return &Client{BaseURL: srv.URL, config: noRetryWait()}
}

// noRetryWait is osvdev's default config without the waits between retries.
func noRetryWait() *osvdev.ClientConfig {
	config := osvdev.DefaultConfig()
	config.BackoffDurationMultiplier = 0
	config.JitterMultiplier = 0
	return &config
}

// The requests and answers of the OSV.dev API, as the test server sees them.
type queryBatchRequest struct {
	Queries []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Version   string `json:"version"`
		PageToken string `json:"page_token"`
	} `json:"queries"`
}

type queryBatchResponse struct {
	Results []queryResult `json:"results"`
}

type queryResult struct {
	Vulns         []queryVuln `json:"vulns"`
	NextPageToken string      `json:"next_page_token,omitempty"`
}

type queryVuln struct {
	ID string `json:"id"`
}

type vulnResponse struct {
	ID      string   `json:"id"`
	Aliases []string `json:"aliases,omitempty"`
}

func goPackage(name, version string) Package {
	return Package{Ecosystem: "Go", Name: name, Version: version}
}

var testPackage = goPackage("example.com/mod", "v1.0.0")

func TestQueryReturnsVulnerabilitiesPerPackage(t *testing.T) {
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
			})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}

	c := newTestClient(t, handler)
	vulnerablePackage, safePackage := goPackage("example.com/vulnerable", "v1.0.0"), goPackage("example.com/safe", "v2.0.0")
	got, err := c.Query(context.Background(), []Package{vulnerablePackage, safePackage})
	if err != nil {
		t.Fatalf("Query returned error: %v", err)
	}

	vulnerable := got[vulnerablePackage]
	if len(vulnerable) != 1 {
		t.Fatalf("got %d vulnerabilities for vulnerable package, want 1: %+v", len(vulnerable), vulnerable)
	}
	if vulnerable[0].ID != "GHSA-aaaa-bbbb-cccc" {
		t.Errorf("ID = %q, want GHSA-aaaa-bbbb-cccc", vulnerable[0].ID)
	}
	if aliases := vulnerable[0].Aliases; len(aliases) != 1 || aliases[0] != "CVE-2026-1234" {
		t.Errorf("Aliases = %q, want [CVE-2026-1234]", aliases)
	}
	if safe, ok := got[safePackage]; ok {
		t.Errorf("got an entry for safe package with zero vulnerabilities, want the key to be absent: %+v", safe)
	}
}

// Packages are deduplicated before querying, and vulnerability IDs before
// fetching, but an ID listed twice for one package is still returned twice.
func TestQueryDeduplicatesPackagesAndVulnIDs(t *testing.T) {
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
	got, err := c.Query(context.Background(), []Package{testPackage, testPackage, {}})
	if err != nil {
		t.Fatalf("Query returned error: %v", err)
	}

	if queryBatchCalls != 1 {
		t.Errorf("querybatch called %d times, want 1", queryBatchCalls)
	}
	if vulnCalls != 1 {
		t.Errorf("GET /v1/vulns/{id} called %d times, want 1 (fetching should be deduplicated across the unique vulnerability ID set, even though the same ID appears twice in this querybatch result)", vulnCalls)
	}
	if len(got[testPackage]) != 2 {
		t.Errorf("got %d vulnerabilities, want 2 (the querybatch result listed the same ID twice for this package, so the returned per-package list is not itself deduplicated, only the underlying fetch is)", len(got[testPackage]))
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

func TestQueryPropagatesHTTPErrors(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	})

	_, err := c.Query(context.Background(), []Package{testPackage})
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

	_, err := c.Query(context.Background(), []Package{testPackage})
	if err == nil {
		t.Fatal("expected error for a result-count mismatch, got nil")
	}
}

// Regression: a /v1/vulns response for another (or no) ID used to be
// accepted, yielding a finding with an empty vulnerability name.
func TestQueryRejectsMismatchedVulnerabilityRecord(t *testing.T) {
	for _, body := range []vulnResponse{{}, {ID: "GO-2"}} {
		c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/querybatch" {
				_ = json.NewEncoder(w).Encode(queryBatchResponse{Results: []queryResult{{Vulns: []queryVuln{{ID: "GO-1"}}}}})
				return
			}
			_ = json.NewEncoder(w).Encode(body)
		})
		if _, err := c.Query(context.Background(), []Package{testPackage}); err == nil {
			t.Errorf("response %+v for GO-1: expected an error, got nil", body)
		}
	}
}

func TestQueryRejectsEmptyVulnerabilityID(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/querybatch" {
			_ = json.NewEncoder(w).Encode(queryBatchResponse{Results: []queryResult{{Vulns: []queryVuln{{ID: ""}}}}})
			return
		}
		t.Errorf("unexpected request: %s", r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	})
	if _, err := c.Query(context.Background(), []Package{testPackage}); err == nil {
		t.Fatal("expected an error for a querybatch vulnerability without an ID, got nil")
	}
}

func TestQueryAcceptsVulnerabilityRecordFetchedByAlias(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/querybatch" {
			_ = json.NewEncoder(w).Encode(queryBatchResponse{Results: []queryResult{{Vulns: []queryVuln{{ID: "GHSA-1"}}}}})
			return
		}
		_ = json.NewEncoder(w).Encode(vulnResponse{ID: "GO-1", Aliases: []string{"GHSA-1", "CVE-2024-1"}})
	})
	got, err := c.Query(context.Background(), []Package{testPackage})
	if err != nil {
		t.Fatalf("Query returned error: %v", err)
	}
	if vs := got[testPackage]; len(vs) != 1 || vs[0].ID != "GO-1" {
		t.Errorf("got %+v, want the GO-1 record", got)
	}
}

func TestQuerySortsByFetchedRecordID(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/querybatch" {
			_ = json.NewEncoder(w).Encode(queryBatchResponse{Results: []queryResult{{Vulns: []queryVuln{{ID: "GHSA-1"}, {ID: "GO-1"}}}}})
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
		if id == "GHSA-1" {
			id = "GO-2"
		}
		_ = json.NewEncoder(w).Encode(vulnResponse{ID: id, Aliases: []string{"GHSA-1"}})
	})
	got, err := c.Query(context.Background(), []Package{testPackage})
	if err != nil {
		t.Fatalf("Query returned error: %v", err)
	}
	vs := got[testPackage]
	if len(vs) != 2 || vs[0].ID != "GO-1" || vs[1].ID != "GO-2" {
		t.Errorf("got %+v, want GO-1 then GO-2", vs)
	}
}

func TestQueryFollowsNextPageToken(t *testing.T) {
	var batchCalls int
	handler := func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/querybatch":
			batchCalls++
			var req queryBatchRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decoding querybatch request: %v", err)
			}
			var resp queryBatchResponse
			for _, q := range req.Queries {
				switch {
				case q.Package.Name == "example.com/big" && q.PageToken == "":
					resp.Results = append(resp.Results, queryResult{Vulns: []queryVuln{{ID: "GO-1"}}, NextPageToken: "page2"})
				case q.Package.Name == "example.com/big" && q.PageToken == "page2":
					resp.Results = append(resp.Results, queryResult{Vulns: []queryVuln{{ID: "GO-2"}}})
				case q.Package.Name == "example.com/small" && q.PageToken == "":
					resp.Results = append(resp.Results, queryResult{Vulns: []queryVuln{{ID: "GO-3"}}})
				default:
					t.Errorf("unexpected query %+v", q)
					resp.Results = append(resp.Results, queryResult{})
				}
			}
			_ = json.NewEncoder(w).Encode(resp)
		case strings.HasPrefix(r.URL.Path, "/v1/vulns/"):
			_ = json.NewEncoder(w).Encode(vulnResponse{ID: strings.TrimPrefix(r.URL.Path, "/v1/vulns/")})
		}
	}

	c := newTestClient(t, handler)
	bigPackage, smallPackage := goPackage("example.com/big", "v1.0.0"), goPackage("example.com/small", "v1.0.0")
	got, err := c.Query(context.Background(), []Package{bigPackage, smallPackage})
	if err != nil {
		t.Fatalf("Query returned error: %v", err)
	}
	if batchCalls != 2 {
		t.Errorf("got %d querybatch calls, want 2 (second one only for the paginated package)", batchCalls)
	}
	big := got[bigPackage]
	if len(big) != 2 || big[0].ID != "GO-1" || big[1].ID != "GO-2" {
		t.Errorf("big = %+v, want GO-1 and GO-2 from both pages", big)
	}
	if small := got[smallPackage]; len(small) != 1 || small[0].ID != "GO-3" {
		t.Errorf("small = %+v, want GO-3", small)
	}
}

func TestQueryStopsRunawayPagination(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(queryBatchResponse{Results: []queryResult{{NextPageToken: "again"}}})
	})
	if _, err := c.Query(context.Background(), []Package{testPackage}); err == nil {
		t.Fatal("expected error for a server that never stops paginating, got nil")
	}
}

func TestQueryRetriesTransientErrors(t *testing.T) {
	var calls int
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			calls++
			if calls == 1 {
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			if calls == 2 {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			_ = json.NewEncoder(w).Encode(queryBatchResponse{Results: []queryResult{{Vulns: []queryVuln{{ID: "GO-1"}}}}})
		default:
			_ = json.NewEncoder(w).Encode(vulnResponse{ID: "GO-1"})
		}
	})

	got, err := c.Query(context.Background(), []Package{testPackage})
	if err != nil {
		t.Fatalf("Query returned error: %v", err)
	}
	if calls != 3 {
		t.Errorf("got %d querybatch attempts, want 3", calls)
	}
	if len(got[testPackage]) != 1 {
		t.Errorf("got %+v, want one vulnerability", got)
	}
}

func TestQueryDoesNotRetryClientErrors(t *testing.T) {
	var calls int
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusBadRequest)
	})
	if _, err := c.Query(context.Background(), []Package{testPackage}); err == nil {
		t.Fatal("expected error for a 400 response, got nil")
	}
	if calls != 1 {
		t.Errorf("got %d attempts, want 1 (a 400 is not transient)", calls)
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
	if _, err := c.Query(context.Background(), []Package{testPackage}); err != nil {
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
	if _, err := c.Query(context.Background(), []Package{testPackage}); err != nil {
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
	_, err := c.Query(context.Background(), []Package{testPackage})
	if err == nil {
		t.Fatal("expected error when fetching vulnerability details fails, got nil")
	}
}

func TestFetchVulnerabilitiesEmptyIDs(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request for empty IDs: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	})

	got, err := c.fetchVulnerabilities(context.Background(), nil, false)
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

	got, err := c.fetchVulnerabilities(context.Background(), ids, false)
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

	var served atomic.Int32
	handler := func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
		if id == "GHSA-1" {
			// Not retried, so the error surfaces at once.
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprint(w, "boom")
			return
		}
		time.Sleep(20 * time.Millisecond)
		served.Add(1)
		_ = json.NewEncoder(w).Encode(vulnResponse{ID: id})
	}

	srv := httptest.NewServer(http.HandlerFunc(handler))
	t.Cleanup(srv.Close)
	c := &Client{BaseURL: srv.URL, VulnFetchConcurrency: 2}

	ids := make([]string, numIDs)
	for i := range ids {
		ids[i] = fmt.Sprintf("GHSA-%d", i)
	}

	_, err := c.fetchVulnerabilities(context.Background(), ids, false)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	// GHSA-1 fails immediately while GHSA-0 is still in flight, so at most
	// the two in-flight requests plus one already-queued one may complete.
	if n := served.Load(); n > 3 {
		t.Errorf("%d of %d requests were served after the first error, want remaining fetches canceled", n, numIDs)
	}
}

func TestFetchVulnerabilitiesFailsWhenParentContextIsCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var once sync.Once
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		once.Do(cancel)
		_ = json.NewEncoder(w).Encode(vulnResponse{ID: strings.TrimPrefix(r.URL.Path, "/v1/vulns/")})
	})
	c.VulnFetchConcurrency = 1

	if got, err := c.fetchVulnerabilities(ctx, []string{"GO-1", "GO-2", "GO-3"}, false); err == nil {
		t.Fatalf("got %d of 3 vulnerabilities and no error, want a cancellation error", len(got))
	}
}

func TestGetSkipsMissingRecordsAndKeepsAffectedVersions(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/vulns/CURL-CVE-2024-11053":
			_, _ = fmt.Fprint(w, `{"id": "CURL-CVE-2024-11053", "aliases": ["CVE-2024-11053"],
				"affected": [{"versions": ["8.11.0", "8.10.1"]}, {"versions": ["7.76.0"]}]}`)
		default:
			http.Error(w, `{"code": 5, "message": "Bug not found."}`, http.StatusNotFound)
		}
	})

	got, err := c.Get(context.Background(), []string{"CURL-CVE-2024-11053", "CURL-CVE-2099-0001"})
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("Get = %+v, want only the existing record", got)
	}
	v := got["CURL-CVE-2024-11053"]
	if want := []string{"8.11.0", "8.10.1", "7.76.0"}; strings.Join(v.AffectedVersions, ",") != strings.Join(want, ",") {
		t.Errorf("AffectedVersions = %v, want %v", v.AffectedVersions, want)
	}
}

func TestGetPropagatesOtherErrors(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		// The body mentions a 404 to check that only the real status counts.
		http.Error(w, `upstream said status="404 Not Found"`, http.StatusForbidden)
	})
	if _, err := c.Get(context.Background(), []string{"CURL-CVE-2024-11053"}); err == nil {
		t.Fatal("Get succeeded on a 403")
	}
}
