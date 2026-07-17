package sbom

import (
	"os"
	"path/filepath"
	"testing"
)

const sampleSBOM = `{
  "name": "/home/sdk/trunk/src/build/images/amd64-usr/stable-4593.2.4-a1/rootfs-with-sysext-pkgs",
  "packages": [
    {
      "name": "fuse",
      "versionInfo": "3.17.0",
      "externalRefs": [
        {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:ebuild/sys-fs/fuse@3.17.0"}
      ]
    },
    {
      "name": "some-go-module",
      "versionInfo": "v1.2.3",
      "externalRefs": [
        {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:golang/example.com/some-go-module@v1.2.3"}
      ]
    },
    {
      "name": "no-refs"
    }
  ]
}`

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}
	return path
}

func TestLoadEbuildPackages(t *testing.T) {
	path := writeTemp(t, "sbom.json", sampleSBOM)

	doc, err := LoadEbuildPackages(path)
	if err != nil {
		t.Fatalf("LoadEbuildPackages returned error: %v", err)
	}

	wantName := "/home/sdk/trunk/src/build/images/amd64-usr/stable-4593.2.4-a1/rootfs-with-sysext-pkgs"
	if doc.Name != wantName {
		t.Errorf("Document.Name = %q, want %q", doc.Name, wantName)
	}

	if len(doc.Packages) != 1 {
		t.Fatalf("got %d packages, want 1 (non-ebuild/no-purl packages should be filtered out): %+v", len(doc.Packages), doc.Packages)
	}

	got := doc.Packages[0]
	want := Package{Category: "sys-fs", Name: "fuse", Version: "3.17.0", PURL: "pkg:ebuild/sys-fs/fuse@3.17.0"}
	if got != want {
		t.Errorf("Packages[0] = %+v, want %+v", got, want)
	}

	if got.CategoryName() != "sys-fs/fuse" {
		t.Errorf("CategoryName() = %q, want %q", got.CategoryName(), "sys-fs/fuse")
	}
}

func TestLoadEbuildPackagesMissingFile(t *testing.T) {
	if _, err := LoadEbuildPackages(filepath.Join(t.TempDir(), "does-not-exist.json")); err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestLoadEbuildPackagesInvalidJSON(t *testing.T) {
	path := writeTemp(t, "bad.json", "{not json")
	if _, err := LoadEbuildPackages(path); err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}
