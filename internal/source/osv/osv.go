// Package osv looks up Go modules and Rust crates in the OSV.dev
// vulnerability database (https://google.github.io/osv.dev/api/), using
// OSV.dev's own Go client for the HTTP calls. See README.md.
package osv

import (
	"cmp"
	"context"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"golang.org/x/sync/errgroup"
	"osv.dev/bindings/go/api"
	"osv.dev/bindings/go/osvdev"
)

// DefaultBaseURL is OSV.dev's production API.
const DefaultBaseURL = osvdev.DefaultBaseURL

const (
	defaultFetchConcurrency = 10  // parallel GET /v1/vulns/{id} requests
	maxPagesPerQuery        = 100 // stops a server that never stops paginating
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
	VulnFetchConcurrency int
	// Config tunes retries and batching; the zero value means osvdev.DefaultConfig().
	Config osvdev.ClientConfig
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

func (c *Client) api() *osvdev.OSVClient {
	client := osvdev.DefaultClient()
	// osvdev appends the endpoint path to the base URL as plain text.
	client.BaseHostURL = strings.TrimSuffix(cmp.Or(c.BaseURL, DefaultBaseURL), "/")
	if c.Config != (osvdev.ClientConfig{}) {
		client.Config = c.Config
	}
	return client
}

// queryIDs returns the vulnerability IDs of each package that has any.
// osvdev splits the queries into requests of at most 1000 but does not
// follow page tokens, so the queries whose results continue on another
// page are re-sent until none do. Results come back in query order.
func (c *Client) queryIDs(ctx context.Context, pkgs []Package) (map[Package][]string, error) {
	var pending []*api.Query
	for _, pkg := range pkgs {
		pending = append(pending, &api.Query{
			Package: &osvschema.Package{Ecosystem: pkg.Ecosystem, Name: pkg.Name},
			Param:   &api.Query_Version{Version: pkg.Version},
		})
	}

	idsByPackage := map[Package][]string{}
	for page := 1; len(pending) > 0; page++ {
		if page > maxPagesPerQuery {
			return nil, fmt.Errorf("osv: querybatch still paginating after %d pages", maxPagesPerQuery)
		}
		resp, err := c.api().QueryBatch(ctx, pending)
		if err != nil {
			return nil, fmt.Errorf("osv: querybatch for %d package(s): %w", len(pending), err)
		}
		if len(resp.GetResults()) != len(pending) {
			return nil, fmt.Errorf("osv: querybatch returned %d result(s) for %d package(s)", len(resp.GetResults()), len(pending))
		}

		var nextPage []*api.Query
		for i, result := range resp.GetResults() {
			query := pending[i]
			pkg := Package{Ecosystem: query.GetPackage().GetEcosystem(), Name: query.GetPackage().GetName(), Version: query.GetVersion()}
			for _, vuln := range result.GetVulns() {
				idsByPackage[pkg] = append(idsByPackage[pkg], vuln.GetId())
			}
			if token := result.GetNextPageToken(); token != "" {
				query.PageToken = token
				nextPage = append(nextPage, query)
			}
		}
		pending = nextPage
	}
	return idsByPackage, nil
}

// fetchVulnerabilities fetches the record of every ID, a few at a time,
// since OSV.dev has no batch endpoint for this. The first error stops
// further requests. With skipMissing, unknown IDs are left out.
func (c *Client) fetchVulnerabilities(parent context.Context, ids []string, skipMissing bool) (map[string]Vulnerability, error) {
	var mu sync.Mutex
	records := map[string]Vulnerability{}

	group, groupCtx := errgroup.WithContext(parent)
	group.SetLimit(positiveOr(c.VulnFetchConcurrency, defaultFetchConcurrency))
	for _, id := range ids {
		if groupCtx.Err() != nil {
			break
		}
		group.Go(func() error {
			// Requests in flight get the parent context: osvdev would keep
			// retrying a canceled request, sleeping between attempts.
			record, err := c.fetchVulnerability(parent, id)
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
	// The ID comes from the server; escaping it keeps it from changing the URL path.
	record, err := c.api().GetVulnByID(ctx, url.PathEscape(id))
	if err != nil {
		return Vulnerability{}, fmt.Errorf("osv: fetching vulnerability %q: %w", id, err)
	}
	if record.GetId() == "" || (record.GetId() != id && !slices.Contains(record.GetAliases(), id)) {
		return Vulnerability{}, fmt.Errorf("osv: fetching vulnerability %q: response is for %q", id, record.GetId())
	}

	vuln := Vulnerability{ID: record.GetId(), Aliases: record.GetAliases()}
	for _, affected := range record.GetAffected() {
		vuln.AffectedVersions = append(vuln.AffectedVersions, affected.GetVersions()...)
	}
	return vuln, nil
}

// isNotFound reports a 404 answer, which osvdev only reports as error text.
func isNotFound(err error) bool {
	return err != nil && strings.Contains(err.Error(), `status="404 `)
}

// positiveOr returns value if it is above zero, and fallback otherwise.
func positiveOr(value, fallback int) int {
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
