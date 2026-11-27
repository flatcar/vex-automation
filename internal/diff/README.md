# diff

Compares the findings of two releases (`Compute`) and renders the "Security fixes" part
of the release notes (`FormatChangelog`). It is pure logic: the caller loads both SBOMs
and matches them against the same data. A wrong "fixed" line would be published as a
claim about the release, so whenever a side could not be fully checked, the pair goes to
`review` instead.

For each (vulnerability, package) pair, each side is reduced to one state: one of the four
VEX statuses, `absent` (package not shipped), `clean` (shipped, no finding) or `unchecked`
(could not be checked). `clean` is how a fix shows up for OSV.dev, which returns nothing
for unaffected versions. The pair of states then lands in a bucket:

```mermaid
flowchart TD
    S(["old state, new state"]) --> A{"was it affected<br/>in the old release?"}
    A -- yes --> N{"and in the new one?"}
    N -- "fixed, not_affected or clean" --> FIX["fixed"]
    N -- "package gone" --> REM["removed"]
    N -- "still affected" --> STILL["still_affected"]
    N -- "unsure" --> REV["review"]
    A -- no --> K{"either side unsure?"}
    K -- yes --> REV
    K -- no --> I{"affected in the new one?"}
    I -- yes --> INT["introduced"]
    I -- no --> DROP(["not reported"])

    classDef good fill:#f0fdf4,stroke:#16a34a,color:#14532d
    classDef bad fill:#fef2f2,stroke:#dc2626,color:#7f1d1d
    classDef unk fill:#fff7ed,stroke:#ea580c,color:#7c2d12
    classDef none fill:#f3f4f6,stroke:#6b7280,color:#111827
    class FIX,REM good
    class STILL,INT bad
    class REV unk
    class DROP none
```

"Unsure" means `under_investigation` or `unchecked`.

The JSON output (`Result`) has every bucket, plus `not_checked`: the packages no source
covers and whether OSV.dev was off. The changelog has only the `fixed` bucket, one
Markdown line per package with its CVEs, so check the JSON before trusting an empty
changelog. Go's `stdlib` and `toolchain` share one "Go" line, and a CVE is held back from
it while either of them is still affected or unchecked.
