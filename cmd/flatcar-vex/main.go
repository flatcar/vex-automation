// Package main is the entrypoint for the flatcar-vex CLI.
package main

import (
	"fmt"
	"os"

	"github.com/flatcar/vex-automation/internal/cli"
)

func main() {
	if err := cli.NewRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
