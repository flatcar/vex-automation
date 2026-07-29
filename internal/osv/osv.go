// Package osv queries the OSV.dev vulnerability database (https://osv.dev)
// for vulnerabilities affecting non-ebuild SBOM packages (golang/cargo
// purls today; see internal/sbom), a large share of Flatcar's SBOM (~1070
// of ~1395 packages in the current production SBOM) that has zero GLSA
// coverage (see docs/plan.md, Decision Log #10).
//
// OSV.dev's API is purl-native and requires no authentication or API key
// (per the public API docs at https://google.github.io/osv.dev/api/).
// Querying it is a two-step process, unlike the single XML corpus GLSA mirrors:
//
//  1. POST /v1/querybatch, one query per unique package purl. This returns
//     only vulnerability IDs (+ a "modified" timestamp), not full advisory
//     data (https://google.github.io/osv.dev/post-v1-querybatch/).
//  2. GET /v1/vulns/{id} for each unique ID returned, to fetch the
//     summary/aliases data actually needed to build a match.Finding
//     (https://google.github.io/osv.dev/get-v1-vulns/).
//
// Unlike GLSA, there is no local version-range matching step here: each
// query already targets the exact installed version (embedded in the query
// purl), so every vulnerability ID OSV.dev returns already applies to that
// installed version. See internal/match.RunOSV for how results are turned
// into Findings.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
)

// DefaultBaseURL is OSV.dev's production API endpoint.
const DefaultBaseURL = "https://api.osv.dev"

// DefaultBatchSize caps how many queries are sent in a single querybatch
// request. OSV.dev documents no hard limit on query count (only on total
// response size: 32MiB over HTTP/1.1, unlimited over HTTP/2), but chunking
// defensively keeps individual requests small and retry-friendly regardless
// of how many packages a caller passes in.
const DefaultBatchSize = 1000

// DefaultVulnFetchConcurrency caps how many GET /v1/vulns/{id} requests are
// in flight at once. Flatcar's SBOM can produce hundreds of unique
// vulnerability IDs to fetch (each requiring its own request, since OSV.dev
// has no batch-fetch-by-ID endpoint); fetching them one at a time would make
// a full run needlessly slow. Kept modest to stay a good API citizen.
const DefaultVulnFetchConcurrency = 10

// Vulnerability is the subset of an OSV.dev vulnerability record needed to
// build a match.Finding: its own ID, any aliases (which may include a CVE
// ID), and a human-readable summary.
type Vulnerability struct {
	// ID is the OSV.dev record's own identifier, e.g. "GHSA-xxxx-xxxx-xxxx"
	// or "GO-2024-1234". Not necessarily a CVE ID.
	ID string
	// Aliases lists other identifiers for the same vulnerability, which may
	// include a "CVE-YYYY-NNNNN" entry if one has been assigned.
	Aliases []string
	// Summary is a short, human-readable description, if the record has one.
	Summary string
}

// CVE returns the first CVE-formatted alias, or ID itself if this
// vulnerability has no CVE alias (common for GHSA/GO advisories that
// haven't been assigned a CVE number).
func (v Vulnerability) CVE() string {
	for _, alias := range v.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			return alias
		}
	}
	return v.ID
}

// Client queries the OSV.dev API.
type Client struct {
	// BaseURL is the API's base URL, DefaultBaseURL if empty. Overridable
	// for tests (see osv_test.go) and for pointing at a private mirror.
	BaseURL string
	// HTTPClient is the client used for all requests, http.DefaultClient
	// if nil.
	HTTPClient *http.Client
	// BatchSize caps how many queries are sent per querybatch request,
	// DefaultBatchSize if zero.
	BatchSize int
	// VulnFetchConcurrency caps how many GET /v1/vulns/{id} requests run
	// concurrently, DefaultVulnFetchConcurrency if zero. Set to 1 to fetch
	// strictly sequentially (e.g. for a private mirror sensitive to
	// concurrent load).
	VulnFetchConcurrency int
}

// NewClient returns a Client configured to talk to the real OSV.dev API.
func NewClient() *Client {
	return &Client{}
}

func (c *Client) baseURL() string {
	if c.BaseURL != "" {
		return c.BaseURL
	}
	return DefaultBaseURL
}

func (c *Client) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}

func (c *Client) batchSize() int {
	if c.BatchSize > 0 {
		return c.BatchSize
	}
	return DefaultBatchSize
}

func (c *Client) vulnFetchConcurrency() int {
	if c.VulnFetchConcurrency > 0 {
		return c.VulnFetchConcurrency
	}
	return DefaultVulnFetchConcurrency
}

// Query returns every OSV.dev vulnerability affecting any of purls (each
// expected to be a versioned purl, e.g. "pkg:golang/example.com/mod@v1.2.3"),
// keyed by the exact purl string passed in. Purls with zero vulnerabilities
// are omitted from the result entirely rather than mapping to an empty
// slice, so callers should use the zero value (nil) of a missing map lookup
// to mean "no vulnerabilities found", not "not queried" -- every purl passed
// in (after deduplication) is always queried. Duplicate purls are queried
// only once; empty strings are ignored. Vulnerabilities for a given purl are
// sorted by ID.
//
// This performs one or more querybatch calls (chunked per BatchSize) plus
// one GET per unique vulnerability ID returned, so callers with a large
// package list should expect this to make many HTTP requests.
func (c *Client) Query(ctx context.Context, purls []string) (map[string][]Vulnerability, error) {
	unique := dedupeNonEmpty(purls)
	if len(unique) == 0 {
		return map[string][]Vulnerability{}, nil
	}

	idsByPurl, err := c.queryBatch(ctx, unique)
	if err != nil {
		return nil, err
	}

	idSet := map[string]bool{}
	for _, ids := range idsByPurl {
		for _, id := range ids {
			idSet[id] = true
		}
	}
	uniqueIDs := make([]string, 0, len(idSet))
	for id := range idSet {
		uniqueIDs = append(uniqueIDs, id)
	}
	sort.Strings(uniqueIDs)

	vulnsByID, err := c.fetchVulnerabilities(ctx, uniqueIDs)
	if err != nil {
		return nil, err
	}

	result := make(map[string][]Vulnerability, len(idsByPurl))
	for purl, ids := range idsByPurl {
		for _, id := range ids {
			if v, ok := vulnsByID[id]; ok {
				result[purl] = append(result[purl], v)
			}
		}
		sort.Slice(result[purl], func(i, j int) bool { return result[purl][i].ID < result[purl][j].ID })
	}
	return result, nil
}

// dedupeNonEmpty returns the distinct, non-empty values in in, order
// preserved by first occurrence.
func dedupeNonEmpty(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// --- querybatch ---

type queryBatchRequest struct {
	Queries []query `json:"queries"`
}

type query struct {
	Package queryPackage `json:"package"`
}

type queryPackage struct {
	PURL string `json:"purl"`
}

type queryBatchResponse struct {
	Results []queryResult `json:"results"`
}

type queryResult struct {
	Vulns []queryVuln `json:"vulns"`
}

type queryVuln struct {
	ID string `json:"id"`
}

// queryBatch calls POST /v1/querybatch for every purl in purls (already
// deduplicated by the caller), chunked to at most batchSize queries per
// request, and returns the vulnerability IDs OSV.dev reports for each purl.
func (c *Client) queryBatch(ctx context.Context, purls []string) (map[string][]string, error) {
	result := make(map[string][]string, len(purls))
	batchSize := c.batchSize()

	for start := 0; start < len(purls); start += batchSize {
		end := start + batchSize
		if end > len(purls) {
			end = len(purls)
		}
		chunk := purls[start:end]

		ids, err := c.queryBatchOnce(ctx, chunk)
		if err != nil {
			return nil, err
		}
		for i, p := range chunk {
			result[p] = ids[i]
		}
	}
	return result, nil
}

// queryBatchOnce performs a single POST /v1/querybatch call for purls,
// returning one []string of vulnerability IDs per input purl, in the same
// order (the API guarantees response ordering matches the request).
func (c *Client) queryBatchOnce(ctx context.Context, purls []string) ([][]string, error) {
	req := queryBatchRequest{Queries: make([]query, len(purls))}
	for i, p := range purls {
		req.Queries[i] = query{Package: queryPackage{PURL: p}}
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("osv: encoding querybatch request: %w", err)
	}

	var resp queryBatchResponse
	if err := c.doJSON(ctx, http.MethodPost, "/v1/querybatch", body, &resp); err != nil {
		return nil, fmt.Errorf("osv: querybatch for %d package(s): %w", len(purls), err)
	}
	if len(resp.Results) != len(purls) {
		return nil, fmt.Errorf("osv: querybatch returned %d result(s) for %d package(s)", len(resp.Results), len(purls))
	}

	out := make([][]string, len(purls))
	for i, r := range resp.Results {
		ids := make([]string, len(r.Vulns))
		for j, v := range r.Vulns {
			ids[j] = v.ID
		}
		out[i] = ids
	}
	return out, nil
}

// --- vulns/{id} ---

type vulnResponse struct {
	ID      string   `json:"id"`
	Aliases []string `json:"aliases"`
	Summary string   `json:"summary"`
}

// fetchVulnerabilities calls GET /v1/vulns/{id} once per id and returns the
// full Vulnerability records, keyed by ID. Requests run concurrently via a
// bounded worker pool (vulnFetchConcurrency workers, or len(ids) if
// smaller) since OSV.dev has no batch-fetch-by-ID endpoint and a large SBOM
// can produce hundreds of unique IDs to fetch; running them one at a time
// would make a full match needlessly slow, and spawning one goroutine per
// ID would scale goroutine count with input size rather than with the
// concurrency limit. On the first error, remaining in-flight/queued
// fetches are canceled and that error is returned.
func (c *Client) fetchVulnerabilities(ctx context.Context, ids []string) (map[string]Vulnerability, error) {
	if len(ids) == 0 {
		return map[string]Vulnerability{}, nil
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		id  string
		v   Vulnerability
		err error
	}

	workers := c.vulnFetchConcurrency()
	if workers > len(ids) {
		workers = len(ids)
	}

	jobs := make(chan string)
	results := make(chan result, len(ids))
	var wg sync.WaitGroup

	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range jobs {
				var resp vulnResponse
				// url.PathEscape guards against a malicious/misbehaving
				// OSV.dev mirror returning an ID containing '/' or other
				// path-altering characters, which would otherwise change
				// which URL path this request actually hits (ids come from
				// an untrusted upstream response, see queryBatch above).
				if err := c.doJSON(ctx, http.MethodGet, "/v1/vulns/"+url.PathEscape(id), nil, &resp); err != nil {
					results <- result{id: id, err: fmt.Errorf("osv: fetching vulnerability %q: %w", id, err)}
					continue
				}
				results <- result{id: id, v: Vulnerability(resp)}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, id := range ids {
			select {
			case jobs <- id:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	out := make(map[string]Vulnerability, len(ids))
	var firstErr error
	for r := range results {
		if r.err != nil {
			if firstErr == nil {
				firstErr = r.err
				cancel() // stop remaining in-flight/queued fetches early
			}
			continue
		}
		out[r.id] = r.v
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

// doJSON performs an HTTP request against path (relative to BaseURL),
// sending body (if non-nil) as the request body, and decodes a JSON
// response into out.
func (c *Client) doJSON(ctx context.Context, method, path string, body []byte, out any) error {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	// url.JoinPath (rather than naive string concatenation) correctly
	// handles a BaseURL with a trailing slash or an existing path
	// component, e.g. a --osv-base-url like "https://mirror.example/" or
	// "https://mirror.example/api/" wouldn't otherwise produce a malformed
	// URL with a doubled or dropped slash.
	fullURL, err := url.JoinPath(c.baseURL(), path)
	if err != nil {
		return fmt.Errorf("building request URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("performing request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // read-only response body, nothing actionable to do with a close error.

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20)) // 32MiB, OSV.dev's own documented HTTP/1.1 response limit.
	if err != nil {
		return fmt.Errorf("reading response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(respBody))
		if len(msg) > 500 {
			msg = msg[:500] + "..."
		}
		return fmt.Errorf("%s %s: unexpected status %d: %s", method, path, resp.StatusCode, msg)
	}

	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("decoding response body: %w", err)
	}
	return nil
}
