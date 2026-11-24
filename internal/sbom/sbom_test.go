package sbom

import (
	"os"
	"path/filepath"
	"testing"
)

const sampleSBOM = `{
  "spdxVersion": "SPDX-2.3",
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
      "name": "jwt",
      "versionInfo": "v4.5.1",
      "externalRefs": [
        {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:golang/github.com/golang-jwt/jwt@v4.5.1#v4"}
      ]
    },
    {
      "name": "s3",
      "versionInfo": "v1.88.4",
      "externalRefs": [
        {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:golang/github.com/aws/aws-sdk-go-v2@v1.88.4?type=module#service/s3/"}
      ]
    },
    {
      "name": "stdlib",
      "versionInfo": "go1.25.3",
      "externalRefs": [
        {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:golang/stdlib@1.25.3"}
      ]
    },
    {
      "name": "linux-kernel",
      "versionInfo": "6.12.1",
      "externalRefs": [
        {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:generic/linux-kernel@6.12.1"}
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

	wantOSV := []Package{
		{Category: "golang", Name: "example.com/some-go-module", Version: "v1.2.3", PURL: "pkg:golang/example.com/some-go-module@v1.2.3"},
		{Category: "cargo", Name: "some-crate", Version: "2.0.0", PURL: "pkg:cargo/some-crate@2.0.0"},
		// Regression: the golang subpath is part of the module path.
		{Category: "golang", Name: "github.com/golang-jwt/jwt/v4", Version: "v4.5.1", PURL: "pkg:golang/github.com/golang-jwt/jwt@v4.5.1#v4"},
		{Category: "golang", Name: "github.com/aws/aws-sdk-go-v2/service/s3", Version: "v1.88.4", PURL: "pkg:golang/github.com/aws/aws-sdk-go-v2@v1.88.4?type=module#service/s3/"},
		// Regression: OSV.dev knows stdlib versions without the "go" prefix.
		{Category: "golang", Name: "stdlib", Version: "1.25.3", PURL: "pkg:golang/stdlib@1.25.3"},
	}
	if len(doc.OSVPackages) != len(wantOSV) {
		t.Fatalf("got %d OSV packages, want %d: %+v", len(doc.OSVPackages), len(wantOSV), doc.OSVPackages)
	}
	for i, w := range wantOSV {
		if doc.OSVPackages[i] != w {
			t.Errorf("OSVPackages[%d] = %+v, want %+v", i, doc.OSVPackages[i], w)
		}
	}

	wantSkipped := map[string]string{
		"devel-internal-pkg": "purl does not name a module that OSV.dev can be queried about",
		"malformed-ebuild":   "malformed ebuild purl",
		"no-version-golang":  "purl does not name a module that OSV.dev can be queried about",
		"other-ref-type":     "no purl",
		"linux-kernel":       "unsupported purl type",
		"no-refs":            "no purl",
	}
	if len(doc.Skipped) != len(wantSkipped) {
		t.Fatalf("got %d skipped packages, want %d: %+v", len(doc.Skipped), len(wantSkipped), doc.Skipped)
	}
	for _, sk := range doc.Skipped {
		if want, ok := wantSkipped[sk.Name]; !ok || sk.Reason != want {
			t.Errorf("skipped %+v, want reason %q", sk, want)
		}
	}
}

func TestLoadRejectsUnusableSBOMs(t *testing.T) {
	tests := map[string]string{
		"empty object":   `{}`,
		"null":           `null`,
		"not SPDX":       `{"bomFormat": "CycloneDX", "packages": [{"name": "x", "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:ebuild/a/b@1"}]}]}`,
		"no packages":    `{"spdxVersion": "SPDX-2.3", "packages": []}`,
		"nothing usable": `{"spdxVersion": "SPDX-2.3", "packages": [{"name": "no-refs"}]}`,
	}
	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writeTemp(t, "sbom.json", content)); err == nil {
				t.Error("expected error, got nil")
			}
		})
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
