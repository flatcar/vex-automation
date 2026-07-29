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
      "name": "some-crate",
      "versionInfo": "2.0.0",
      "externalRefs": [
        {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:cargo/some-crate@2.0.0"}
      ]
    },
    {
      "name": "devel-internal-pkg",
      "versionInfo": "(devel)",
      "externalRefs": [
        {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:golang/../internal-pkg@(devel)"}
      ]
    },
    {
      "name": "malformed-ebuild",
      "versionInfo": "1.0",
      "externalRefs": [
        {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:ebuild/no-slash@1.0"}
      ]
    },
    {
      "name": "no-version-golang",
      "versionInfo": "",
      "externalRefs": [
        {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:golang/example.com/no-version"}
      ]
    },
    {
      "name": "other-ref-type",
      "versionInfo": "1.0",
      "externalRefs": [
        {"referenceCategory": "OTHER", "referenceType": "cpe23Type", "referenceLocator": "cpe:2.3:a:example:example:1.0"}
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

func TestLoad(t *testing.T) {
	path := writeTemp(t, "sbom.json", sampleSBOM)

	doc, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	wantName := "/home/sdk/trunk/src/build/images/amd64-usr/stable-4593.2.4-a1/rootfs-with-sysext-pkgs"
	if doc.Name != wantName {
		t.Errorf("Document.Name = %q, want %q", doc.Name, wantName)
	}

	if len(doc.Packages) != 1 {
		t.Fatalf("got %d ebuild packages, want 1: %+v", len(doc.Packages), doc.Packages)
	}
	got := doc.Packages[0]
	want := Package{Category: "sys-fs", Name: "fuse", Version: "3.17.0", PURL: "pkg:ebuild/sys-fs/fuse@3.17.0"}
	if got != want {
		t.Errorf("Packages[0] = %+v, want %+v", got, want)
	}
	if got.CategoryName() != "sys-fs/fuse" {
		t.Errorf("CategoryName() = %q, want %q", got.CategoryName(), "sys-fs/fuse")
	}

	if len(doc.OSVPackages) != 2 {
		t.Fatalf("got %d OSV packages, want 2 (golang + cargo, devel-internal excluded): %+v", len(doc.OSVPackages), doc.OSVPackages)
	}
	wantGo := Package{Category: "golang", Name: "example.com/some-go-module", Version: "v1.2.3", PURL: "pkg:golang/example.com/some-go-module@v1.2.3"}
	wantCargo := Package{Category: "cargo", Name: "some-crate", Version: "2.0.0", PURL: "pkg:cargo/some-crate@2.0.0"}
	if doc.OSVPackages[0] != wantGo {
		t.Errorf("OSVPackages[0] = %+v, want %+v", doc.OSVPackages[0], wantGo)
	}
	if doc.OSVPackages[1] != wantCargo {
		t.Errorf("OSVPackages[1] = %+v, want %+v", doc.OSVPackages[1], wantCargo)
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "does-not-exist.json")); err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestLoadInvalidJSON(t *testing.T) {
	path := writeTemp(t, "bad.json", "{not json")
	if _, err := Load(path); err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}
