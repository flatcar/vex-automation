package cli

import (
	"bytes"
	"log"
	"log/slog"
	"os"
	"strings"
	"testing"
)

func TestNewRootCmdMetadata(t *testing.T) {
	cmd := NewRootCmd()
	if cmd.Use != "flatcar-vex" {
		t.Errorf("Use = %q, want %q", cmd.Use, "flatcar-vex")
	}
	if cmd.Short == "" {
		t.Error("Short description must not be empty")
	}
}

func TestRootCmdHelp(t *testing.T) {
	cmd := NewRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if !strings.Contains(buf.String(), "flatcar-vex") {
		t.Errorf("help output missing command name: %q", buf.String())
	}
}

func TestRootCmdVersion(t *testing.T) {
	cmd := NewRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--version"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if !strings.Contains(buf.String(), "dev") {
		t.Errorf("version output = %q, want to contain %q", buf.String(), "dev")
	}
}

func TestRootCmdVerboseControlsInfoLogs(t *testing.T) {
	f := writeDiffFixture(t)
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() {
		log.SetOutput(os.Stderr)
		slog.SetLogLoggerLevel(slog.LevelInfo)
	})

	for _, tc := range []struct {
		args     []string
		wantInfo bool
	}{
		{nil, false},
		{[]string{"--verbose"}, true},
		{[]string{"-v"}, true},
	} {
		logs.Reset()
		args := append([]string{"--old-sbom", f.oldSBOM, "--new-sbom", f.newSBOM, "--glsa-dir", f.glsaDir, "--osv=false"}, tc.args...)
		if _, err := execDiff(t, args...); err != nil {
			t.Fatalf("%v: diff failed: %v", tc.args, err)
		}
		if !strings.Contains(logs.String(), "OSV.dev matching disabled") {
			t.Errorf("%v: warning missing from logs:\n%s", tc.args, logs.String())
		}
		if got := strings.Contains(logs.String(), "diff computed"); got != tc.wantInfo {
			t.Errorf("%v: info logged = %v, want %v:\n%s", tc.args, got, tc.wantInfo, logs.String())
		}
	}
}
