// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/jay94ks/mydcd/internal/app"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/engine"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type onceString struct {
	value string
	set   bool
}

func (v *onceString) String() string { return v.value }
func (v *onceString) Set(s string) error {
	if v.set || s == "" {
		return errors.New("option must have a value and occur once")
	}
	v.value = s
	v.set = true
	return nil
}
func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
func run(args []string, out, diagnostic io.Writer) int {
	f := flag.NewFlagSet("mydcd", flag.ContinueOnError)
	f.SetOutput(diagnostic)
	var file onceString
	var version, check bool
	f.Var(&file, "config", "node YAML file (required)")
	f.BoolVar(&version, "version", false, "print version")
	f.BoolVar(&check, "check-config", false, "validate without opening node runtime resources")
	f.Usage = func() {
		fmt.Fprintln(diagnostic, "mydcd --config NODE.yaml run|check|init [options]|join [options]|adopt --plan FILE (offline source preparation)")
		f.PrintDefaults()
	}
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return fail(diagnostic, err, 2)
	}
	args = f.Args()
	if version || len(args) == 1 && args[0] == "version" {
		fmt.Fprintln(out, "mydcd 1")
		return 0
	}
	if len(args) > 0 && args[0] == "init" {
		if check {
			return fail(diagnostic, errors.New("init cannot be combined with check-config"), 2)
		}
		return runInit(args[1:], file.value, out, diagnostic)
	}
	if len(args) > 0 && args[0] == "join" {
		if check {
			return fail(diagnostic, errors.New("join cannot be combined with check-config"), 2)
		}
		return runJoin(args[1:], file.value, out, diagnostic)
	}
	if len(args) > 1 || len(args) == 1 && args[0] != "run" && args[0] != "check" {
		return fail(diagnostic, errors.New("usage: mydcd --config NODE.yaml run|check|init [options]|join [options]"), 2)
	}
	if file.value == "" {
		return fail(diagnostic, errors.New("--config is required"), 2)
	}
	c, err := config.LoadNode(file.value)
	if err != nil {
		return fail(diagnostic, err, 2)
	}
	if check || len(args) == 1 && args[0] == "check" {
		if err = app.CheckNodeApps(c); err != nil {
			return fail(diagnostic, err, 2)
		}
		if err = checkDocker(c); err != nil {
			return fail(diagnostic, err, 1)
		}
		fmt.Fprintln(out, "valid node configuration, version=1")
		return 0
	}
	runtime, err := app.Open(c)
	if err != nil {
		return fail(diagnostic, err, 1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// A restored daemon can need its original peers to replay the durable
	// checkpoint. Recovering is a live state, not an init-command deadline:
	// keep the same runtime until installation is proven or it is stopped.
	_, err = runtime.ResumeInstallation(ctx)
	if err != nil {
		if ctx.Err() == nil || !errors.Is(err, ctx.Err()) {
			// Cleanup must not hide the startup cause if an original native
			// owner takes time to close. This is the same eventual error.
			fmt.Fprintf(diagnostic, "mydcd installation failed before cleanup: %v\n", err)
		}
		closeErr := runtime.Close()
		if ctx.Err() != nil && errors.Is(err, ctx.Err()) {
			if closeErr != nil {
				return fail(diagnostic, closeErr, 1)
			}
			return 0
		}
		return fail(diagnostic, errors.Join(err, closeErr), 1)
	}

	if err = runtime.Mesh.ListenUnix(c.Node.ManagementSocket); err != nil {
		_ = runtime.Close()
		return fail(diagnostic, err, 1)
	}
	if err = json.NewEncoder(out).Encode(map[string]any{"event": "started", "node": c.Node.ID, "listener": runtime.Mesh.Addr().String(), "management_socket": runtime.Mesh.ManagementAddr().String(), "control": "election/recovery; query status"}); err != nil {
		_ = runtime.Close()
		return fail(diagnostic, err, 1)
	}
	for {
		select {
		case <-runtime.IdentityRestart():
			if err = runtime.Close(); err != nil {
				return fail(diagnostic, err, 1)
			}
			runtime, err = app.Open(c)
			if err != nil {
				return fail(diagnostic, err, 1)
			}
			if _, err = runtime.ResumeInstallation(ctx); err != nil {
				_ = runtime.Close()
				return fail(diagnostic, err, 1)
			}
			if err = runtime.Mesh.ListenUnix(c.Node.ManagementSocket); err != nil {
				_ = runtime.Close()
				return fail(diagnostic, err, 1)
			}
			continue
		case <-ctx.Done():
		case err = <-runtime.Engine().Failure():
			_ = runtime.Close()
			return fail(diagnostic, err, 70)
		}
		break
	}
	if err = runtime.Close(); err != nil {
		return fail(diagnostic, err, 1)
	}
	return 0
}
func fail(out io.Writer, err error, code int) int { fmt.Fprintln(out, err); return code }

// checkDocker reaches the network module's Docker Engine and checks its
// version, so 'check' finds an Engine too old for managed bridges before run.
func checkDocker(c config.Node) error {
	m := c.Modules["network"]
	if !m.Enabled {
		return nil
	}
	var local config.NetworkLocal
	if err := m.Decode(&local); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	d, err := engine.Open(ctx, local.DockerSocket, "mydcd-check")
	if err != nil {
		return fmt.Errorf("network module Docker %s: %w", local.DockerSocket, err)
	}
	return d.Close()
}
