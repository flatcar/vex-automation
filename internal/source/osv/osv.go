// Package osv is a small client for the OSV.dev vulnerability database
// (https://google.github.io/osv.dev/api/). The API needs no authentication.
//
// Looking up packages takes two steps, because the batch endpoint only
// returns vulnerability IDs:
//
//  1. POST /v1/querybatch: which vulnerability IDs affect each package version.
//  2. GET /v1/vulns/{id}: the full record of each of those IDs.
//
// Flatcar images ship Go and Rust binaries that Gentoo's GLSAs don't
// cover, so OSV.dev fills that gap: Match uses Query for them, and
// the diff command uses Get to fetch curl's own advisories.
package osv

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
)

// DefaultBaseURL is OSV.dev's production API.
const DefaultBaseURL = "https://api.osv.dev"

const (
	defaultBatchSize        = 1000 // queries per querybatch request
	defaultFetchConcurrency = 10   // parallel GET /v1/vulns/{id} requests
	defaultRetryBackoff     = time.Second

	maxPagesPerQuery = 100 // stops a server that never stops paginating
	maxAttempts      = 3   // per request, for rate-limit and server errors
	maxRetryAfter    = time.Minute
	maxResponseSize  = 32 << 20 // OSV.dev's documented HTTP/1.1 limit
)

// Package is one package version to look up, e.g. ecosystem "Go", name
// "golang.org/x/net", version "v0.38.0".
type Package struct {
	Ecosystem string
	Name      string
	Version   string
}

// Vulnerability is the part of an OSV.dev record this tool uses.
type Vulnerability struct {
	ID string // e.g. "GHSA-xxxx-xxxx-xxxx" or "GO-2024-1234"
	// Aliases are other IDs of the same vulnerability, often a CVE.
	Aliases []string
	// AffectedVersions are all versions the record lists as affected.
	AffectedVersions []string
}

// Client talks to the OSV.dev API. The zero value uses the defaults; the
// fields exist for tests and private mirrors.
type Client struct {
	BaseURL              string
	BatchSize            int
	VulnFetchConcurrency int
	RetryBackoff         time.Duration
}

// Query returns the vulnerabilities affecting each package. Packages
// without vulnerabilities are not in the result.
func (c *Client) Query(ctx context.Context, pkgs []Package) (map[Package][]Vulnerability, error) {
	idsByPackage, err := c.queryIDs(ctx, unique(pkgs))
	if err != nil {
		return nil, err
	}

	var allIDs []string
	for _, ids := range idsByPackage {
		allIDs = append(allIDs, ids...)
	}
	records, err := c.fetchVulnerabilities(ctx, unique(allIDs), false)
	if err != nil {
		return nil, err
	}

	result := map[Package][]Vulnerability{}
	for pkg, ids := range idsByPackage {
		for _, id := range ids {
			record, ok := records[id]
			if !ok {
				return nil, fmt.Errorf("osv: vulnerability %q returned by querybatch was not fetched", id)
			}
			result[pkg] = append(result[pkg], record)
		}
		// Sort by the records' own IDs: a record fetched by an alias
		// carries a different ID than the one querybatch returned.
		slices.SortFunc(result[pkg], func(a, b Vulnerability) int { return strings.Compare(a.ID, b.ID) })
	}
	return result, nil
}

// Get fetches the records with the given IDs. IDs OSV.dev has no record
// for are left out instead of failing.
func (c *Client) Get(ctx context.Context, ids []string) (map[string]Vulnerability, error) {
	return c.fetchVulnerabilities(ctx, ids, true)
}

// --- Step 1: POST /v1/querybatch ---

type queryBatchRequest struct {
	Queries []query `json:"queries"`
}

type query struct {
	Package   queryPackage `json:"package"`
	Version   string       `json:"version"`
	PageToken string       `json:"page_token,omitempty"`
}

type queryPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
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

func newQuery(pkg Package) query {
	return query{Package: queryPackage{Name: pkg.Name, Ecosystem: pkg.Ecosystem}, Version: pkg.Version}
}

func (q query) pkg() Package {
	return Package{Ecosystem: q.Package.Ecosystem, Name: q.Package.Name, Version: q.Version}
}

// queryIDs returns the vulnerability IDs of each package that has any.
func (c *Client) queryIDs(ctx context.Context, pkgs []Package) (map[Package][]string, error) {
	idsByPackage := map[Package][]string{}
	for batch := range slices.Chunk(pkgs, positiveOr(c.BatchSize, defaultBatchSize)) {
		if err := c.queryBatch(ctx, batch, idsByPackage); err != nil {
			return nil, err
		}
	}
	return idsByPackage, nil
}

// queryBatch sends one querybatch request for pkgs, then re-sends the
// queries whose results continue on another page, until none do. Results
// come back in request order.
func (c *Client) queryBatch(ctx context.Context, pkgs []Package, idsByPackage map[Package][]string) error {
	var pending []query
	for _, pkg := range pkgs {
		pending = append(pending, newQuery(pkg))
	}

	for page := 1; len(pending) > 0; page++ {
		if page > maxPagesPerQuery {
			return fmt.Errorf("osv: querybatch still paginating after %d pages", maxPagesPerQuery)
		}
		var resp queryBatchResponse
		if err := c.do(ctx, http.MethodPost, "/v1/querybatch", queryBatchRequest{Queries: pending}, &resp); err != nil {
			return fmt.Errorf("osv: querybatch for %d package(s): %w", len(pending), err)
		}
		if len(resp.Results) != len(pending) {
			return fmt.Errorf("osv: querybatch returned %d result(s) for %d package(s)", len(resp.Results), len(pending))
		}

		var nextPage []query
		for i, result := range resp.Results {
			pkg := pending[i].pkg()
			for _, vuln := range result.Vulns {
				idsByPackage[pkg] = append(idsByPackage[pkg], vuln.ID)
			}
			if result.NextPageToken != "" {
				next := pending[i]
				next.PageToken = result.NextPageToken
				nextPage = append(nextPage, next)
			}
		}
		pending = nextPage
	}
	return nil
}

// --- Step 2: GET /v1/vulns/{id} ---

type vulnResponse struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Affected []struct {
		Versions []string `json:"versions"`
	} `json:"affected"`
}

// fetchVulnerabilities fetches the record of every ID, a few at a time,
// since OSV.dev has no batch endpoint for this. The first error cancels
// the remaining requests. With skipMissing, unknown IDs are left out.
func (c *Client) fetchVulnerabilities(parent context.Context, ids []string, skipMissing bool) (map[string]Vulnerability, error) {
	var mu sync.Mutex
	records := map[string]Vulnerability{}

	group, ctx := errgroup.WithContext(parent)
	group.SetLimit(positiveOr(c.VulnFetchConcurrency, defaultFetchConcurrency))
	for _, id := range ids {
		if ctx.Err() != nil {
			break
		}
		group.Go(func() error {
			record, err := c.fetchVulnerability(ctx, id)
			if skipMissing && isNotFound(err) {
				return nil
			}
			if err != nil {
				return err
			}
			mu.Lock()
			records[id] = record
			mu.Unlock()
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return nil, err
	}
	// A canceled parent stops the loop above without any request failing.
	if err := parent.Err(); err != nil {
		return nil, fmt.Errorf("osv: fetching vulnerabilities: %w", err)
	}
	return records, nil
}

func (c *Client) fetchVulnerability(ctx context.Context, id string) (Vulnerability, error) {
	var resp vulnResponse
	// The ID comes from the server; escaping it keeps it from changing the URL path.
	if err := c.do(ctx, http.MethodGet, "/v1/vulns/"+url.PathEscape(id), nil, &resp); err != nil {
		return Vulnerability{}, fmt.Errorf("osv: fetching vulnerability %q: %w", id, err)
	}
	if resp.ID == "" || (resp.ID != id && !slices.Contains(resp.Aliases, id)) {
		return Vulnerability{}, fmt.Errorf("osv: fetching vulnerability %q: response is for %q", id, resp.ID)
	}

	vuln := Vulnerability{ID: resp.ID, Aliases: resp.Aliases}
	for _, affected := range resp.Affected {
		vuln.AffectedVersions = append(vuln.AffectedVersions, affected.Versions...)
	}
	return vuln, nil
}

// --- HTTP ---

// statusError is an HTTP answer other than 200 OK.
type statusError struct {
	method, path string
	code         int
	body         string
	retryAfter   time.Duration // from the Retry-After header, 0 if absent
}

func (e *statusError) Error() string {
	return fmt.Sprintf("%s %s: unexpected status %d: %s", e.method, e.path, e.code, e.body)
}

func isNotFound(err error) bool {
	var status *statusError
	return errors.As(err, &status) && status.code == http.StatusNotFound
}

// isTransient reports whether the request may succeed when retried:
// the server was rate limiting (429) or failing (5xx).
func isTransient(err error) (*statusError, bool) {
	var status *statusError
	ok := errors.As(err, &status) && (status.code == http.StatusTooManyRequests || status.code >= 500)
	return status, ok
}

// do sends a request with request (if not nil) as its JSON body and decodes
// the JSON answer into response. Transient errors are retried, doubling the
// wait each time unless the server says how long to wait.
func (c *Client) do(ctx context.Context, method, path string, request, response any) error {
	backoff := positiveOr(c.RetryBackoff, defaultRetryBackoff)
	for attempt := 1; ; attempt++ {
		err := c.doOnce(ctx, method, path, request, response)
		status, transient := isTransient(err)
		if !transient || attempt == maxAttempts {
			return err
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("%w (giving up retry: %w)", err, ctx.Err())
		case <-time.After(retryWait(status.retryAfter, backoff)):
		}
		backoff *= 2
	}
}

// retryWait is the server's Retry-After (capped) if it sent one, else backoff.
func retryWait(retryAfter, backoff time.Duration) time.Duration {
	if retryAfter > 0 {
		return min(retryAfter, maxRetryAfter)
	}
	return backoff
}

func (c *Client) doOnce(ctx context.Context, method, path string, request, response any) error {
	fullURL, err := url.JoinPath(cmp.Or(c.BaseURL, DefaultBaseURL), path)
	if err != nil {
		return fmt.Errorf("building request URL: %w", err)
	}
	var body io.Reader
	if request != nil {
		encoded, err := json.Marshal(request)
		if err != nil {
			return fmt.Errorf("encoding request: %w", err)
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, body)
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("performing request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // nothing to do about a close error on a read body

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return fmt.Errorf("reading response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return newStatusError(method, path, resp, respBody)
	}
	if err := json.Unmarshal(respBody, response); err != nil {
		return fmt.Errorf("decoding response body: %w", err)
	}
	return nil
}

func newStatusError(method, path string, resp *http.Response, body []byte) *statusError {
	text := strings.TrimSpace(string(body))
	if len(text) > 500 {
		text = text[:500] + "..."
	}
	err := &statusError{method: method, path: path, code: resp.StatusCode, body: text}
	if seconds, parseErr := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After"))); parseErr == nil && seconds > 0 {
		err.retryAfter = time.Duration(seconds) * time.Second
	}
	return err
}

// positiveOr returns value if it is above zero, and fallback otherwise.
func positiveOr[T int | time.Duration](value, fallback T) T {
	if value > 0 {
		return value
	}
	return fallback
}

// unique returns items without duplicates or zero values, in their original order.
func unique[T comparable](items []T) []T {
	var zero T
	seen := map[T]bool{}
	var out []T
	for _, item := range items {
		if item != zero && !seen[item] {
			seen[item] = true
			out = append(out, item)
		}
	}
	return out
}
