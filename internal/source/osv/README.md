# source/osv

[OSV.dev](https://osv.dev) as a vulnerability source for the Go modules and Rust crates
compiled into Flatcar's binaries, which Gentoo writes no advisories for. It needs network
access; `--osv=false` turns it off.

`Client` wraps OSV.dev's own Go client (`osv.dev/bindings/go/osvdev`), which does the HTTP
calls and retries them on network errors, rate limits and server errors. `Query` sends
package versions to the batch endpoint, which returns the IDs of the vulnerabilities
affecting each exact version, and follows pagination (the library does not); `Get` fetches
full records, because only those list the CVE aliases, and leaves out IDs OSV.dev answers
404 for. Records are fetched ten at a time. The library's waits between retries ignore the
context, so `--osv-timeout` can be overrun by one wait, up to about 15 seconds.

`Match` turns the answers into findings. Two consequences of how OSV.dev works shape it.
Every finding is `affected`, because OSV.dev only answers for vulnerable versions; a fixed
vulnerability shows up as no finding at all, which is why `diff` treats silence from
OSV.dev as a fix. And OSV.dev often holds several records for one vulnerability (a GitHub
`GHSA-...`, a Go `GO-...`, the CVE). Records that point at each other are grouped and
reported under their CVE IDs, so a CVE found by both Gentoo and OSV.dev ends up in one VEX
statement rather than two.

## curl

Gentoo's curl GLSAs bundle years of CVEs under one `lt <latest>` range, so a release whose
curl already had a fix still matches, and `diff` would list long-fixed CVEs as newly
fixed. curl publishes precise per-CVE advisories on OSV.dev (`CURL-CVE-...`), listing
every affected release. `CurlAdvisoryIDs` says which of them to fetch for the GLSA
findings, and `ApplyCurlAdvisories` turns a curl GLSA finding into `not_affected` when
curl's own advisory does not list the installed upstream version. On one real release pair
this cut the wrongly listed curl CVEs from 39 to 3. Only `diff` uses it.
