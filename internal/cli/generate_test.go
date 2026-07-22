package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testSBOM = `{
  "name": "/home/sdk/trunk/src/build/images/amd64-usr/stable-4593.2.4-a1/rootfs-with-sysext-pkgs",
  "packages": [
    {
      "name": "fuse",
      "versionInfo": "3.17.0",
      "externalRefs": [
        {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:ebuild/sys-fs/fuse@3.17.0"}
      ]
    }
  ]
}`

const testGLSA = `<?xml version="1.0" encoding="UTF-8"?>
<glsa id="202604-03">
    <title>FUSE: Multiple Vulnerabilities</title>
    <affected>
        <package name="sys-fs/fuse" arch="*">
            <unaffected range="ge">3.18.1</unaffected>
            <vulnerable range="lt">3.18.1</vulnerable>
        </package>
    </affected>
    <references>
        <uri link="https://nvd.nist.gov/vuln/detail/CVE-2026-33150">CVE-2026-33150</uri>
    </references>
</glsa>`

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

func TestGenerateCmdWritesVEXToStdout(t *testing.T) {
	dir := t.TempDir()
	sbomPath := filepath.Join(dir, "sbom.json")
	glsaDir := filepath.Join(dir, "glsa")
	if err := os.Mkdir(glsaDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeTestFile(t, sbomPath, testSBOM)
	writeTestFile(t, filepath.Join(glsaDir, "glsa-202604-03.xml"), testGLSA)

	cmd := NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"generate", "--sbom", sbomPath, "--glsa-dir", glsaDir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute returned error: %v\noutput: %s", err, out.String())
	}

	var doc map[string]any
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %s", err, out.String())
	}

	statements, ok := doc["statements"].([]any)
	if !ok || len(statements) != 1 {
		t.Fatalf("expected exactly 1 statement, got: %v", doc["statements"])
	}
	stmt := statements[0].(map[string]any)
	if stmt["status"] != "affected" {
		t.Errorf("status = %v, want %q", stmt["status"], "affected")
	}

	products, _ := stmt["products"].([]any)
	if len(products) != 1 {
		t.Fatalf("expected 1 product, got %v", stmt["products"])
	}
	product := products[0].(map[string]any)
	wantProductID := "pkg:generic/flatcar-container-linux@4593.2.4-a1?channel=stable"
	if product["@id"] != wantProductID {
		t.Errorf("product @id = %v, want %q (derived from SBOM document name)", product["@id"], wantProductID)
	}
}

func TestGenerateCmdWritesVEXToFile(t *testing.T) {
	dir := t.TempDir()
	sbomPath := filepath.Join(dir, "sbom.json")
	glsaDir := filepath.Join(dir, "glsa")
	outPath := filepath.Join(dir, "out", "flatcar.vex.json")
	if err := os.Mkdir(glsaDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeTestFile(t, sbomPath, testSBOM)
	writeTestFile(t, filepath.Join(glsaDir, "glsa-202604-03.xml"), testGLSA)

	cmd := NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"generate", "--sbom", sbomPath, "--glsa-dir", glsaDir, "-o", outPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute returned error: %v\noutput: %s", err, out.String())
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("reading output file: %v", err)
	}
	if !strings.Contains(string(data), "CVE-2026-33150") {
		t.Errorf("output file missing expected CVE: %s", data)
	}
}

func TestGenerateCmdMissingRequiredFlags(t *testing.T) {
	cmd := NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"generate"})

	if err := cmd.Execute(); err == nil {
		t.Error("expected an error when --sbom/--glsa-dir are missing, got nil")
	}
}

func TestGenerateCmdMissingSBOMFile(t *testing.T) {
	dir := t.TempDir()
	glsaDir := filepath.Join(dir, "glsa")
	if err := os.Mkdir(glsaDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	cmd := NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"generate", "--sbom", filepath.Join(dir, "does-not-exist.json"), "--glsa-dir", glsaDir})

	if err := cmd.Execute(); err == nil {
		t.Error("expected an error for a missing SBOM file, got nil")
	}
}

func TestDeriveProductID(t *testing.T) {
	cases := []struct {
		name string
		want string
	}{
		{
			name: "/home/sdk/trunk/src/build/images/amd64-usr/stable-4593.2.4-a1/rootfs-with-sysext-pkgs",
			want: "pkg:generic/flatcar-container-linux@4593.2.4-a1?channel=stable",
		},
		{
			name: "/home/sdk/trunk/src/build/images/amd64-usr/beta-4600.0.0/rootfs-with-sysext-pkgs",
			want: "pkg:generic/flatcar-container-linux@4600.0.0?channel=beta",
		},
		{
			name: "unrecognized-name",
			want: "pkg:generic/flatcar-container-linux",
		},
	}

	for _, tc := range cases {
		if got := deriveProductID(tc.name); got != tc.want {
			t.Errorf("deriveProductID(%q) = %q, want %q", tc.name, got, tc.want)
		}
	}
}
