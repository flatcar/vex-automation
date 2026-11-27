package vuln

import (
	"testing"

	"github.com/flatcar/vex-automation/internal/sbom"
)

func TestSortFindingsOrdersBySourceThenRefIDForIdenticalCVEAndPackage(t *testing.T) {
	// Same CVE and same package.FullName()/Version (a scenario that
	// could arise once both GLSA and OSV.dev are matched together), but two
	// different sources: order must still be fully deterministic.
	pkg := sbom.Package{Ecosystem: sbom.Ebuild, Category: "sys-fs", Name: "fuse", Version: "3.17.0", PURL: "pkg:ebuild/sys-fs/fuse@3.17.0"}
	findings := []Finding{
		{CVE: "CVE-2026-1", Source: SourceOSV, RefID: "GHSA-b", Package: pkg},
		{CVE: "CVE-2026-1", Source: SourceGLSA, RefID: "202604-02", Package: pkg},
		{CVE: "CVE-2026-1", Source: SourceGLSA, RefID: "202604-01", Package: pkg},
	}

	Sort(findings)

	want := []struct{ source, refID string }{
		{SourceGLSA, "202604-01"},
		{SourceGLSA, "202604-02"},
		{SourceOSV, "GHSA-b"},
	}
	for i, w := range want {
		if findings[i].Source != w.source || findings[i].RefID != w.refID {
			t.Errorf("findings[%d] = {Source: %q, RefID: %q}, want {%q, %q}", i, findings[i].Source, findings[i].RefID, w.source, w.refID)
		}
	}
}
