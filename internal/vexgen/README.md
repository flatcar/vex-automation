# vexgen

Turns findings into an OpenVEX document (`Build`), using the official
[go-vex](https://github.com/openvex/go-vex) library. This is the output of `generate`:
per vulnerability, whether this Flatcar release is affected, fixed, not affected or still
under investigation, so users and their scanners don't have to work it out from the SBOM.

Findings are grouped by vulnerability ID and each group becomes one statement about the
release as a whole, with the packages involved listed under it. When the findings of one
vulnerability disagree, the statement takes the most severe status (see
[`vuln`](../vuln)) and lists only the packages with that status. A real statement:

```json
{
  "vulnerability": { "name": "CVE-2001-1413" },
  "products": [{
    "@id": "pkg:generic/flatcar-container-linux@4593.2.4-a1?channel=stable",
    "subcomponents": [{ "identifiers": { "purl": "pkg:ebuild/app-arch/ncompress@5.0-r2" } }]
  }],
  "status": "fixed"
}
```

`affected` statements carry an action that cites the advisories per source, e.g. "see
Gentoo GLSA 202604-03; OSV.dev advisory GO-2026-1". The document's `tooling` field
records which sources were used, so a reader can tell a GLSA-only document from a full
one. Statements are sorted by vulnerability ID and the document ID is derived from the
content (go-vex's canonical ID).
