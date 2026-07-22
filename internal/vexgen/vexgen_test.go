package vexgen

import (
	"testing"
	"time"

	"github.com/openvex/go-vex/pkg/vex"

	"github.com/flatcar/vex-automation/internal/match"
	"github.com/flatcar/vex-automation/internal/sbom"
)

func TestBuildRequiresProductID(t *testing.T) {
	if _, err := Build(nil, Metadata{}); err == nil {
		t.Error("expected error when ProductID is empty, got nil")
	}
}

func TestBuildGroupsByCVEAndStatus(t *testing.T) {
	ts := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	findings := []match.Finding{
		{
			CVE: "CVE-2026-33150", GLSAID: "202604-03", Affected: true,
			Package: sbom.Package{Category: "sys-fs", Name: "fuse", Version: "3.17.0", PURL: "pkg:ebuild/sys-fs/fuse@3.17.0"},
		},
		{
			CVE: "CVE-2026-33150", GLSAID: "202604-03", Affected: true,
			Package: sbom.Package{Category: "sys-fs", Name: "fuse2", Version: "3.17.0", PURL: "pkg:ebuild/sys-fs/fuse2@3.17.0"},
		},
		{
			CVE: "CVE-2026-33179", GLSAID: "202604-03", Affected: false,
			Package: sbom.Package{Category: "sys-fs", Name: "fuse", Version: "3.18.1", PURL: "pkg:ebuild/sys-fs/fuse@3.18.1"},
		},
	}

	doc, err := Build(findings, Metadata{Author: "test-author", ProductID: "pkg:generic/flatcar@1.0", Timestamp: ts})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}

	if doc.Author != "test-author" {
		t.Errorf("Author = %q, want %q", doc.Author, "test-author")
	}
	if doc.ID == "" {
		t.Error("expected a canonical document ID to be generated, got empty string")
	}

	if len(doc.Statements) != 2 {
		t.Fatalf("got %d statements, want 2 (one per distinct CVE+status group): %+v", len(doc.Statements), doc.Statements)
	}

	affected := doc.Statements[0]
	if affected.Vulnerability.Name != "CVE-2026-33150" {
		t.Errorf("Statements[0].Vulnerability.Name = %q, want CVE-2026-33150", affected.Vulnerability.Name)
	}
	if affected.Status != vex.StatusAffected {
		t.Errorf("Statements[0].Status = %q, want %q", affected.Status, vex.StatusAffected)
	}
	if affected.ActionStatement == "" {
		t.Error("expected a non-empty ActionStatement for an affected statement")
	}
	subs := affected.Products[0].Subcomponents
	if len(subs) != 2 {
		t.Fatalf("got %d subcomponents, want 2 (fuse and fuse2): %+v", len(subs), subs)
	}
	// Subcomponents are sorted by PURL string; "fuse2@..." sorts before
	// "fuse@..." because '2' (0x32) < '@' (0x40) in ASCII.
	if subs[0].Identifiers[vex.PURL] != "pkg:ebuild/sys-fs/fuse2@3.17.0" {
		t.Errorf("Subcomponents[0] PURL = %q", subs[0].Identifiers[vex.PURL])
	}
	if subs[1].Identifiers[vex.PURL] != "pkg:ebuild/sys-fs/fuse@3.17.0" {
		t.Errorf("Subcomponents[1] PURL = %q", subs[1].Identifiers[vex.PURL])
	}

	fixed := doc.Statements[1]
	if fixed.Status != vex.StatusFixed {
		t.Errorf("Statements[1].Status = %q, want %q", fixed.Status, vex.StatusFixed)
	}
	if fixed.ActionStatement != "" {
		t.Errorf("expected no ActionStatement for a fixed statement, got %q", fixed.ActionStatement)
	}
}

func TestBuildDeduplicatesSubcomponents(t *testing.T) {
	findings := []match.Finding{
		{
			CVE: "CVE-2026-1", GLSAID: "202604-01", Affected: true,
			Package: sbom.Package{Category: "sys-fs", Name: "fuse", Version: "1.0", PURL: "pkg:ebuild/sys-fs/fuse@1.0"},
		},
		{ // duplicate PURL from matching a second CVE that got merged into this group by mistake would be a bug; here simulate the same finding twice.
			CVE: "CVE-2026-1", GLSAID: "202604-01", Affected: true,
			Package: sbom.Package{Category: "sys-fs", Name: "fuse", Version: "1.0", PURL: "pkg:ebuild/sys-fs/fuse@1.0"},
		},
	}

	doc, err := Build(findings, Metadata{ProductID: "pkg:generic/flatcar@1.0"})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if len(doc.Statements) != 1 {
		t.Fatalf("got %d statements, want 1", len(doc.Statements))
	}
	if got := len(doc.Statements[0].Products[0].Subcomponents); got != 1 {
		t.Errorf("got %d subcomponents, want 1 (duplicate PURL should be deduplicated)", got)
	}
}

func TestBuildEmptyFindings(t *testing.T) {
	doc, err := Build(nil, Metadata{ProductID: "pkg:generic/flatcar@1.0"})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if len(doc.Statements) != 0 {
		t.Errorf("got %d statements, want 0", len(doc.Statements))
	}
}

func TestBuildActionStatementJoinsMultipleGLSAIDs(t *testing.T) {
	findings := []match.Finding{
		{
			CVE: "CVE-2026-1", GLSAID: "202604-02", Affected: true,
			Package: sbom.Package{Category: "sys-fs", Name: "fuse", Version: "1.0", PURL: "pkg:ebuild/sys-fs/fuse@1.0"},
		},
		{
			CVE: "CVE-2026-1", GLSAID: "202604-01", Affected: true,
			Package: sbom.Package{Category: "sys-fs", Name: "fuse2", Version: "1.0", PURL: "pkg:ebuild/sys-fs/fuse2@1.0"},
		},
	}

	doc, err := Build(findings, Metadata{ProductID: "pkg:generic/flatcar@1.0"})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if len(doc.Statements) != 1 {
		t.Fatalf("got %d statements, want 1", len(doc.Statements))
	}

	const want = "Update the affected package(s) to a version that resolves this CVE (see Gentoo GLSA 202604-01, 202604-02)."
	if got := doc.Statements[0].ActionStatement; got != want {
		t.Errorf("ActionStatement = %q, want %q", got, want)
	}
}
