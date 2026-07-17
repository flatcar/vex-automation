package cli

import (
	"bytes"
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
