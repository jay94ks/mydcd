// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"os/signal"
	"syscall"

	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
)

func main() {
	if syscall.Setpriority(syscall.PRIO_PROCESS, 0, 10) != nil {
		os.Exit(2)
	}
	f := flag.NewFlagSet("lifecycle-compiler", flag.ContinueOnError)
	var e checker.CompileEnvironment
	f.StringVar(&e.Input, "input", "/input", "read-only job input")
	f.StringVar(&e.Work, "work", "/work", "bounded job scratch")
	f.StringVar(&e.Output, "output", "/output", "approved job artifact output")
	f.StringVar(&e.Cache, "cache", "/cache", "approved tenant Go build cache")
	f.StringVar(&e.GoRoot, "go-root", "/opt/go", "fixed image toolchain")
	if f.Parse(os.Args[1:]) != nil || f.NArg() != 0 {
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	report, err := checker.ExecuteCompileBatch(ctx, e)
	// Public output is bounded metadata only; private compiler diagnostics are
	// in the owned output root. No idle loop or next-job listener follows.
	if json.NewEncoder(os.Stdout).Encode(report) != nil {
		os.Exit(2)
	}
	if err != nil {
		os.Exit(1)
	}
}
