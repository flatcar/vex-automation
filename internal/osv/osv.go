// Package osv queries the OSV.dev vulnerability database (https://osv.dev)
// for vulnerabilities affecting non-ebuild SBOM packages (golang/cargo
// purls today; see internal/sbom), a large share of Flatcar's SBOM (~1070
// of ~1395 packages in the current production SBOM) that has zero GLSA
// coverage (see docs/plan.md, Decision Log #10).
//
// OSV.dev's API requires no authentication or API key
// (per the public API docs at https://google.github.io/osv.dev/api/).
// Querying it is a two-step process, unlike the single XML corpus GLSA mirrors:
//
//  1. POST /v1/querybatch, one query per unique package (by OSV ecosystem
//     and name for golang/cargo, see newQuery, else by purl). This returns
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
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
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
	// AffectedVersions lists every version the record enumerates as
	// affected, across all of its affected packages.
	AffectedVersions []string
}

// CVEs returns every CVE-formatted identifier among ID and Aliases, sorted
// and deduplicated, or just ID if there are none (common for GHSA/GO
// advisories that haven't been assigned a CVE number). A single OSV.dev
// record can cover several CVEs, and each must be reported.
func (v Vulnerability) CVEs() []string {
	seen := map[string]bool{}
	var cves []string
	for _, id := range append([]string{v.ID}, v.Aliases...) {
		if strings.HasPrefix(id, "CVE-") && !seen[id] {
			seen[id] = true
			cves = append(cves, id)
		}
	}
	if len(cves) == 0 {
		return []string{v.ID}
	}
	sort.Strings(cves)
	return cves
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
	// RetryBackoff is the delay before the first retry of a rate-limited
	// or server-error response, DefaultRetryBackoff if zero.
	RetryBackoff time.Duration
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

	vulnsByID, err := c.fetchVulnerabilities(ctx, uniqueIDs, false)
	if err != nil {
		return nil, err
	}

	result := make(map[string][]Vulnerability, len(idsByPurl))
	for purl, ids := range idsByPurl {
		for _, id := range ids {
			v, ok := vulnsByID[id]
			if !ok {
				return nil, fmt.Errorf("osv: vulnerability %q returned by querybatch was not fetched", id)
			}
			result[purl] = append(result[purl], v)
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
	Package   queryPackage `json:"package"`
	Version   string       `json:"version,omitempty"`
	PageToken string       `json:"page_token,omitempty"`
}

// queryPackage identifies the package to query: by Name and Ecosystem
// (with the version in query.Version) for the ecosystems in purlEcosystems,
// else by PURL. OSV.dev lowercases golang purls on lookup, so a purl query
// for a mixed-case module path like github.com/Azure/... silently matches
// nothing, while the name query is case-preserving.
type queryPackage struct {
	PURL      string `json:"purl,omitempty"`
	Name      string `json:"name,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
}

// purlEcosystems maps purl types to OSV.dev ecosystem names.
var purlEcosystems = map[string]string{
	"golang": "Go",
	"cargo":  "crates.io",
}

// newQuery builds the querybatch entry for a versioned purl of the form
// "pkg:<type>/<name>@<version>" (qualifiers and subpath, if any, are not
// part of the OSV.dev package identity and are dropped).
func newQuery(purl string) query {
	rest, ok := strings.CutPrefix(purl, "pkg:")
	if ok {
		rest, _, _ = strings.Cut(rest, "#")
		rest, _, _ = strings.Cut(rest, "?")
		typ, nameVersion, _ := strings.Cut(rest, "/")
		at := strings.LastIndex(nameVersion, "@")
		eco := purlEcosystems[strings.ToLower(typ)]
		if eco != "" && at > 0 && at < len(nameVersion)-1 {
			name, nameErr := url.PathUnescape(nameVersion[:at])
			version, versionErr := url.PathUnescape(nameVersion[at+1:])
			if nameErr == nil && versionErr == nil {
				return query{Package: queryPackage{Name: name, Ecosystem: eco}, Version: version}
			}
		}
	}
	return query{Package: queryPackage{PURL: purl}}
}

type queryBatchResponse struct {
	Results []queryResult `json:"results"`
}

type queryResult struct {
	Vulns         []queryVuln `json:"vulns"`
	NextPageToken string      `json:"next_page_token"`
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

// maxPagesPerQuery bounds how many pages are requested for a single purl,
// so a misbehaving server that always returns a page token can't loop
// forever. OSV.dev pages after 1,000 vulnerabilities per query, so this
// allows far more than any real package has.
const maxPagesPerQuery = 100

// queryBatchOnce performs POST /v1/querybatch calls for purls, returning
// one []string of vulnerability IDs per input purl, in the same order (the
// API guarantees response ordering matches the request). OSV.dev paginates
// a query's results when it has too many vulnerabilities, returning a
// next_page_token; such queries are re-sent with that token until every
// page has been collected.
func (c *Client) queryBatchOnce(ctx context.Context, purls []string) ([][]string, error) {
	out := make([][]string, len(purls))
	pending := make([]int, len(purls)) // indices into purls still needing a page
	tokens := make([]string, len(purls))
	for i := range purls {
		pending[i] = i
	}

	for page := 0; len(pending) > 0; page++ {
		if page >= maxPagesPerQuery {
			return nil, fmt.Errorf("osv: querybatch still paginating after %d pages", maxPagesPerQuery)
		}

		req := queryBatchRequest{Queries: make([]query, len(pending))}
		for j, i := range pending {
			req.Queries[j] = newQuery(purls[i])
			req.Queries[j].PageToken = tokens[i]
		}
		body, err := json.Marshal(req)
		if err != nil {
			return nil, fmt.Errorf("osv: encoding querybatch request: %w", err)
		}

		var resp queryBatchResponse
		if err := c.doJSON(ctx, http.MethodPost, "/v1/querybatch", body, &resp); err != nil {
			return nil, fmt.Errorf("osv: querybatch for %d package(s): %w", len(pending), err)
		}
		if len(resp.Results) != len(pending) {
			return nil, fmt.Errorf("osv: querybatch returned %d result(s) for %d package(s)", len(resp.Results), len(pending))
		}

		var next []int
		for j, r := range resp.Results {
			i := pending[j]
			for _, v := range r.Vulns {
				out[i] = append(out[i], v.ID)
			}
			if r.NextPageToken != "" {
				tokens[i] = r.NextPageToken
				next = append(next, i)
			}
		}
		pending = next
	}
	return out, nil
}

// --- vulns/{id} ---

type vulnResponse struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Summary  string   `json:"summary"`
	Affected []struct {
		Versions []string `json:"versions"`
	} `json:"affected"`
}

func (r vulnResponse) vulnerability() Vulnerability {
	v := Vulnerability{ID: r.ID, Aliases: r.Aliases, Summary: r.Summary}
	for _, a := range r.Affected {
		v.AffectedVersions = append(v.AffectedVersions, a.Versions...)
	}
	return v
}

// Get fetches the records with the given IDs. IDs OSV.dev has no record
// for are left out of the result instead of failing the call.
func (c *Client) Get(ctx context.Context, ids []string) (map[string]Vulnerability, error) {
	return c.fetchVulnerabilities(ctx, ids, true)
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
// With skipMissing, IDs answered with 404 are left out instead of failing.
func (c *Client) fetchVulnerabilities(parent context.Context, ids []string, skipMissing bool) (map[string]Vulnerability, error) {
	if len(ids) == 0 {
		return map[string]Vulnerability{}, nil
	}

	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	type result struct {
		id      string
		v       Vulnerability
		missing bool
		err     error
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
					var se *statusError
					if skipMissing && errors.As(err, &se) && se.code == http.StatusNotFound {
						results <- result{id: id, missing: true}
						continue
					}
					results <- result{id: id, err: fmt.Errorf("osv: fetching vulnerability %q: %w", id, err)}
					continue
				}
				if resp.ID == "" || (resp.ID != id && !slices.Contains(resp.Aliases, id)) {
					results <- result{id: id, err: fmt.Errorf("osv: fetching vulnerability %q: response is for %q", id, resp.ID)}
					continue
				}
				results <- result{id: id, v: resp.vulnerability()}
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
		if r.missing {
			continue
		}
		out[r.id] = r.v
	}
	if firstErr != nil {
		return nil, firstErr
	}
	// A canceled parent stops the job feeder without any worker failing,
	// which would otherwise return a silently incomplete map.
	if err := parent.Err(); err != nil {
		return nil, fmt.Errorf("osv: fetching vulnerabilities: %w", err)
	}
	return out, nil
}

// maxAttempts is how many times a request is tried in total when OSV.dev
// answers with a transient status (429 or 5xx).
const maxAttempts = 3

// DefaultRetryBackoff is the delay before the first retry of a transient
// failure; it doubles on each further retry, unless the server sends a
// Retry-After header.
const DefaultRetryBackoff = time.Second

// maxRetryAfter caps how long a server-sent Retry-After may delay a retry.
const maxRetryAfter = time.Minute

// statusError is returned for a non-200 response.
type statusError struct {
	method, path string
	code         int
	msg          string
	retryAfter   time.Duration
}

func (e *statusError) Error() string {
	return fmt.Sprintf("%s %s: unexpected status %d: %s", e.method, e.path, e.code, e.msg)
}

func (e *statusError) transient() bool {
	return e.code == http.StatusTooManyRequests || e.code >= 500
}

func (c *Client) retryBackoff() time.Duration {
	if c.RetryBackoff > 0 {
		return c.RetryBackoff
	}
	return DefaultRetryBackoff
}

// doJSON performs an HTTP request against path (relative to BaseURL),
// sending body (if non-nil) as the request body, and decodes a JSON
// response into out. Rate-limited (429) and server-error (5xx) responses
// are retried up to maxAttempts times with exponential backoff, honoring a
// Retry-After header given in seconds.
func (c *Client) doJSON(ctx context.Context, method, path string, body []byte, out any) error {
	backoff := c.retryBackoff()
	for attempt := 1; ; attempt++ {
		err := c.doJSONOnce(ctx, method, path, body, out)
		var se *statusError
		if err == nil || !errors.As(err, &se) || !se.transient() || attempt >= maxAttempts {
			return err
		}
		timer := time.NewTimer(retryWait(se.retryAfter, backoff))
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("%w (giving up retry: %w)", err, ctx.Err())
		case <-timer.C:
		}
		backoff *= 2
	}
}

// retryWait returns how long to wait before the next attempt: the server's
// Retry-After (capped at maxRetryAfter) if given, else backoff.
func retryWait(retryAfter, backoff time.Duration) time.Duration {
	if retryAfter > 0 {
		return min(retryAfter, maxRetryAfter)
	}
	return backoff
}

// doJSONOnce performs a single attempt of doJSON.
func (c *Client) doJSONOnce(ctx context.Context, method, path string, body []byte, out any) error {
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
		se := &statusError{method: method, path: path, code: resp.StatusCode, msg: msg}
		if secs, err := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After"))); err == nil && secs > 0 {
			se.retryAfter = time.Duration(secs) * time.Second
		}
		return se
	}

	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("decoding response body: %w", err)
	}
	return nil
}
