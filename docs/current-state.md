# Flatcar Security/CVE Handling — Current State (As-Is)

> **Compiled from:** direct inspection of `flatcar/scripts`, `flatcar/Flatcar`,
> `flatcar/jenkins-os`, `flatcar/flatcar-build-scripts`, live GitHub issue/PR queries, the
> real `security.gentoo.org` RSS feed, and a Slack conversation with **Dongsu Park**
> (2026-07-17). Every fact below was verified against source (file paths and commands are
> cited in §7); nothing here is speculative.
>
> **Scope note:** this document describes **what exists today**. It is deliberately *not*
> a proposal — the target VEX design is a separate follow-up document.

**Contents:** [1. Executive Summary](#1-executive-summary) · [2. Overall Map](#2-overall-map) ·
[3. Path A — GLSA Build Gate](#3-path-a--glsa-build-gate-lifecycle) ·
[4. Path B — Routine Updates](#4-path-b--routine--weekly-package-updates-independent-of-glsa) ·
[5. Path C — Manual Advisory Tracking](#5-path-c--manual-advisory-issue-tracking) ·
[6. Data Sources Inventory](#6-data-sources-inventory) ·
[7. Known Gaps](#7-known-gaps-in-the-current-state) ·
[8. Verified Facts Reference](#8-verified-facts-reference)

---

## 1. Executive Summary

There are **two largely decoupled mechanisms** by which vulnerabilities get addressed in
Flatcar today, plus a **third, purely manual** communication layer sitting on top of both.
There is currently **no machine-readable VEX output anywhere** in this system.

| # | Mechanism | Covers | Automated? | Blocks a build? |
|---|-----------|--------|:---:|:---:|
| **A** | `glsa-check` build gate | Only CVEs Gentoo wrote a formal GLSA for | Detection: ✅ · Triage: ❌ | ✅ Yes |
| **B** | Routine / weekly package updates | The majority of real-world CVE fixes | Sync: ✅ · Review/merge: ❌ | ❌ No |
| **C** | Manual advisory issues (`flatcar/Flatcar`) | Human-curated superset, independent of A/B | ❌ 100% manual | ❌ No |

> **Key correction from Dongsu Park:** A and B are **largely independent**. Most CVEs are
> fixed as a *side effect* of ordinary package-freshness bumps (Path B) — not because a
> GLSA ever fired. GLSA/`glsa-check` (Path A) only ever sees "a limited list of CVEs."

---

## 2. Overall Map

```mermaid
flowchart TD
    subgraph UPSTREAM["🌐 Upstream Sources"]
        GENTOO_GIT["Gentoo glsa.git<br/>(continuous commits)"]
        GENTOO_RSYNC["rsync://rsync.gentoo.org<br/>/gentoo-portage/metadata/glsa"]
        GENTOO_RSS["security.gentoo.org/glsa/feed.rss<br/>✅ verified live"]
        GENTOO_ANNOUNCE["gentoo-announce<br/>mailing list"]
        OTHER_FEEDS["oss-security, Golang, Rust<br/>security mailing lists"]
        KERNEL_CVE["lore.kernel.org/linux-cve-announce<br/>(Atom feed)"]
    end

    GENTOO_GIT --> GENTOO_RSYNC
    GENTOO_GIT --> GENTOO_RSS
    GENTOO_GIT --> GENTOO_ANNOUNCE

    subgraph SCRIPTS["📦 flatcar/scripts repo"]
        GLSA_SYNC["update-metadata-glsa.yaml<br/>cron '0 7 1 * *' — monthly<br/>FULL unfiltered mirror"]
        GLSA_DIR["metadata/glsa/*.xml<br/>~3.8k files, all Gentoo history"]
        PKG_LIST["portage-stable-packages-list<br/>776 curated packages"]
        WEEKLY_SYNC["update-portage-stable-packages<br/>-from-list.yaml — cron weekly (Mon)"]
        BUILD["Image build<br/>(build_image_util.sh)"]
        TEST_CONTENT["test_image_content.sh<br/>glsa_image()"]
        ALLOWLIST["GLSA_ALLOWLIST<br/>hardcoded bash array"]
        SHOW_CHANGES["show-changes / image_changes.sh<br/>(flatcar-build-scripts)"]
        KERNEL_CVE_SCRIPT["show-fixed-kernel-cves.py<br/>kernel-only, reporting only"]
        CHANGELOG["changelog/security/*.md<br/>manual PR convention — no CI check"]
    end

    GENTOO_RSYNC -->|"rsync --archive<br/>no relevance filtering"| GLSA_SYNC --> GLSA_DIR
    PKG_LIST --> WEEKLY_SYNC -->|"opens draft PR"| SCRIPTS_PR_WEEKLY["Weekly package-update PR"]
    GLSA_DIR --> BUILD --> TEST_CONTENT
    TEST_CONTENT -->|"glsa-check-$BOARD -t all"| GLSA_DIR
    TEST_CONTENT --- ALLOWLIST
    TEST_CONTENT -->|"unallowlisted match"| BUILD_FAIL["❌ Build FAILS"]
    BUILD --> SHOW_CHANGES
    KERNEL_CVE --> KERNEL_CVE_SCRIPT --> SHOW_CHANGES
    SHOW_CHANGES --> RELEASE_NOTES["Release changelog text"]
    CHANGELOG -->|"aggregated at release time"| RELEASE_NOTES

    subgraph HUMAN["🧑 Manual Human Process (Security Team)"]
        RUNBOOK["Daily runbook (SECURITY.md)<br/>Primary/Secondary feeds checked by hand"]
        GH_ISSUE["flatcar/Flatcar issue<br/>labels: security, advisory, cvss/*<br/>⚠️ 100% MANUALLY WRITTEN"]
    end

    BUILD_FAIL --> RUNBOOK
    GENTOO_ANNOUNCE --> RUNBOOK
    OTHER_FEEDS --> RUNBOOK
    RUNBOOK -->|"human writes issue"| GH_ISSUE
    GH_ISSUE -->|"someone bumps the package<br/>(e.g. Krzesimir), PR merged"| PKG_UPDATE_PR["Package update PR"]
    PKG_UPDATE_PR -->|"manually re-types CVE IDs<br/>into changelog fragment"| CHANGELOG

    subgraph RELEASE["🚀 Release / Distribution"]
        FEED_XML["releases-&lt;channel&gt;.xml<br/>(Atom feed)"]
        FEED_JSON["releases-&lt;channel&gt;.json"]
        SBOM["flatcar_production_image_sbom.json<br/>SPDX, per version/board/channel<br/>authoritative package+version source"]
    end

    RELEASE_NOTES --> FEED_XML
    RELEASE_NOTES --> FEED_JSON
    BUILD --> SBOM

    classDef upstream fill:#eef2ff,stroke:#4f46e5,color:#1e1b4b
    classDef scripts fill:#ecfeff,stroke:#0891b2,color:#083344
    classDef human fill:#fff7ed,stroke:#ea580c,color:#7c2d12
    classDef release fill:#f0fdf4,stroke:#16a34a,color:#14532d
    classDef fail fill:#fef2f2,stroke:#dc2626,color:#7f1d1d,stroke-width:2px

    class GENTOO_GIT,GENTOO_RSYNC,GENTOO_RSS,GENTOO_ANNOUNCE,OTHER_FEEDS,KERNEL_CVE upstream
    class GLSA_SYNC,GLSA_DIR,PKG_LIST,WEEKLY_SYNC,BUILD,TEST_CONTENT,ALLOWLIST,SHOW_CHANGES,KERNEL_CVE_SCRIPT,CHANGELOG,SCRIPTS_PR_WEEKLY scripts
    class RUNBOOK,GH_ISSUE,PKG_UPDATE_PR human
    class FEED_XML,FEED_JSON,SBOM,RELEASE_NOTES release
    class BUILD_FAIL fail
```

---

## 3. Path A — GLSA Build-Gate Lifecycle

This is the **only fully automated *detection*** mechanism in the current system — but it
only fires for the subset of CVEs that have a formal Gentoo GLSA, and only at **build
time**, against whatever is currently being built (not already-shipped releases).

```mermaid
sequenceDiagram
    autonumber
    participant Gentoo as Gentoo glsa.git
    participant Cron as update-metadata-glsa.yaml<br/>(monthly cron)
    participant Tree as scripts repo<br/>metadata/glsa/*.xml
    participant Build as Image build
    participant Check as glsa-check-$BOARD
    participant Allow as GLSA_ALLOWLIST
    participant Dongsu as Security team (human)
    participant Issue as flatcar/Flatcar issue

    Gentoo->>Cron: full rsync mirror (unfiltered, no relevance check)
    Cron->>Tree: commit full GLSA corpus (e.g. PR #3879)
    Note over Tree: ~3.8k XML files, all Gentoo history —<br/>no package-relevance filtering (data is small, not worth it)
    Build->>Check: glsa-check -t all against built ROOT
    Check->>Tree: match installed pkg/version vs GLSA ranges
    Check->>Allow: diff result against allowlist
    alt GLSA applies AND not allowlisted
        Check-->>Build: ❌ FAIL
        Build-->>Dongsu: investigate build failure
        Dongsu->>Issue: manually write structured issue<br/>(Name / CVEs / CVSSs / Action Needed / Summary)
    else GLSA applies but allowlisted
        Check-->>Build: ✅ pass (documented exception)
    else no match
        Check-->>Build: ✅ pass
    end
```

**Source:** `build_library/test_image_content.sh` → `glsa_image()`, invoked from
`build_image_util.sh` (`test_image_content()`).

---

## 4. Path B — Routine / Weekly Package Updates (Independent of GLSA)

Per Dongsu: **most real CVE fixes happen here**, not via Path A. A package gets bumped for
ordinary freshness reasons; if that bump happens to cross a CVE-fixed version boundary, the
CVE is fixed as a side effect — with no GLSA or `glsa-check` failure ever involved.

```mermaid
flowchart LR
    A["portage-stable-packages-list<br/>776 curated packages"] --> B["Weekly sync job<br/>update-portage-stable-packages-from-list.yaml"]
    B --> C["Draft PR: package version bumps"]
    C --> D["Human review + merge<br/>(e.g. Krzesimir)"]
    D --> E["changelog/updates/*.md or<br/>changelog/security/*.md<br/>(manual — human decides category)"]
    E --> F["Release notes aggregation"]
    F --> G["releases-&lt;channel&gt;.xml / .json<br/>explicit CVE list per release"]

    style A fill:#e1f5fe,stroke:#0288d1,color:#000
    style G fill:#e8f5e9,stroke:#2e7d32,color:#000
    style D fill:#fff3e0,stroke:#ef6c00,color:#000
```

---

## 5. Path C — Manual Advisory Issue Tracking

Confirmed directly by Dongsu: **"Those are all manually created"** — referring to the
`advisory`-labeled issues in `flatcar/Flatcar` (**331 total, 46 currently open** as of this
review — see §8).

```mermaid
flowchart TD
    S1["📖 Daily runbook (SECURITY.md)"] --> S2{"Human scans upstream sources"}
    S2 --> S3["Gentoo GLSAs"]
    S2 --> S4["oss-security mailing list"]
    S2 --> S5["Golang / Rust security announcements"]
    S2 --> S6["glsa-check build failures"]
    S3 & S4 & S5 & S6 --> S7{"Human judgement:<br/>is this Flatcar-relevant?"}
    S7 -->|"yes, no existing issue"| S8["Manually create GitHub issue<br/>labels: security, advisory, cvss/*"]
    S7 -->|"yes, issue exists"| S9["Manually edit existing issue<br/>to append new CVE"]
    S7 -->|"no"| S10["Ignored — no record kept"]
    S8 --> S11["Issue stays open until someone<br/>manually verifies fix and closes it"]
    S9 --> S11

    style S7 fill:#fff7ed,stroke:#ea580c,color:#000
    style S10 fill:#f5f5f5,stroke:#9e9e9e,color:#000
    style S8 fill:#fef2f2,stroke:#dc2626,color:#000
```

**Observed issue body template** (consistent across years/authors, still 100% hand-typed):

```markdown
Name: <package>
CVEs: <CVE-1>, <CVE-2>, ...
CVSSs: <score-1>, <score-2>, ...
Action Needed: update to >= <version>
Summary: <upstream description>
```

Severity labels — `cvss/CRITICAL` (≥9), `cvss/HIGH` (7–9), `cvss/MEDIUM` (4–7) — are also
assigned by hand, consistently enough to look templated, but no code anywhere produces them.
A single issue (e.g. [#2188](https://github.com/flatcar/Flatcar/issues/2188)) can bundle
**multiple CVEs with different `Action Needed` thresholds** — an important edge case for any
future automation.

---

## 6. Data Sources Inventory

```mermaid
flowchart TB
    subgraph Detection["🔎 Detection / Input Sources"]
        direction LR
        D1["Gentoo GLSA rsync mirror<br/>(full corpus, monthly)"]
        D2["security.gentoo.org/glsa/feed.rss<br/>near real-time, verified working"]
        D3["gentoo-announce<br/>mailing list"]
        D4["lore.kernel.org/linux-cve-announce<br/>(kernel-only)"]
        D5["oss-security / Golang / Rust<br/>mailing lists — human-read only"]
    end

    subgraph GroundTruth["✅ Ground Truth for 'what do we ship'"]
        direction LR
        G1["portage-stable + coreos-overlay<br/>≈599 packages (446 + 153)<br/>curated subset of Gentoo's ~19,000"]
        G2["flatcar_production_image_sbom.json<br/>SPDX; 'ebuild' purl type =<br/>exact category/pkg + version"]
    end

    subgraph Output["📤 Published Outputs"]
        direction LR
        O1["releases-&lt;channel&gt;.xml/.json<br/>explicit fixed-CVE lists per release"]
        O2["flatcar/Flatcar GitHub issues<br/>security, advisory, cvss/* labels"]
        O3["changelog/security/*.md fragments"]
    end

    Detection --> GroundTruth --> Output

    classDef detect fill:#eef2ff,stroke:#4f46e5,color:#1e1b4b
    classDef truth fill:#f0fdf4,stroke:#16a34a,color:#14532d
    classDef out fill:#fefce8,stroke:#ca8a04,color:#713f12
    class D1,D2,D3,D4,D5 detect
    class G1,G2 truth
    class O1,O2,O3 out
```

> `G1` is a reliable **existence proxy** ("is this package used by Flatcar at all") but not
> sufficient alone to prove something is in the *production-shipped* image (it could be
> SDK-only or sysext-only). `G2` (the SBOM) is authoritative for that finer distinction and
> is also the only source that ties an exact **version** to a **released** artifact.

---

## 7. Known Gaps in the Current State

| # | Gap | Why it matters |
|---|-----|-----------------|
| 1 | **No automated relevance filtering** | A human must eyeball every new GLSA/CVE against Flatcar's package list; nothing does this today. |
| 2 | **GLSA coverage is narrow** | Most real fixes happen via Path B, invisible to `glsa-check` entirely, since A and B are decoupled. |
| 3 | **Advisory issue creation is 100% manual** | `SECURITY.md` claims *"we... use automation tools to create a new issue"* — confirmed **false** by Dongsu. |
| 4 | **CVE IDs re-typed by hand, twice** | Once into the GitHub issue, again into `changelog/security/*.md` — no automated link, no CI enforcement that the fragment is even added. |
| 5 | **No VEX output anywhere** | Nothing here produces a machine-readable VEX document; the closest analogues are hand-written issue bodies and release-note CVE lists. |
| 6 | **No queryable "shipped version X ↔ still-affected-by CVE Y" record** | That information lives only in prose (issue comments like *"Fixed in Beta 4722.1.0, Stable 4593.2.4, LTS 4081.3.9"*). |

---

## 8. Verified Facts Reference

Every quantitative claim above was checked against a primary source on 2026-07-17:

| Claim | Verified value | Source |
|---|---|---|
| GLSA sync cadence | `cron: '0 7 1 * *'` (monthly, 1st) | `scripts/.github/workflows/update-metadata-glsa.yaml` |
| Weekly package sync cadence | `cron: '0 7 * * 1'` (weekly, Monday) | `scripts/.github/workflows/update-portage-stable-packages-from-list.yaml` |
| Local GLSA XML mirror size | 3,817 files | `find scripts -iname 'glsa-*.xml' \| wc -l` |
| Curated package list size | 776 entries | `scripts/.github/workflows/portage-stable-packages-list` |
| Package tree size (ground truth) | 446 (`portage-stable`) + 153 (`coreos-overlay`) = **599** | GitHub API tree listing, `flatcar-archive/portage-stable` & `flatcar-archive/coreos-overlay` @ `main` |
| Build gate function | `glsa_image()` → `glsa-check-$BOARD -t all` vs `GLSA_ALLOWLIST` | `scripts/build_library/test_image_content.sh` |
| `advisory`-labeled issues | 331 total, 46 open | GitHub Search API, `repo:flatcar/Flatcar label:advisory` |
| "Automation" claim in docs | Present, contradicted by Dongsu | `Flatcar/SECURITY.md` line 28 |
| GLSA RSS feed | Live and working | `https://security.gentoo.org/glsa/feed.rss` |
| GLSA notification mailing list | `gentoo-announce` | Gentoo project documentation |
