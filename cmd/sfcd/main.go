// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/jay94ks/seafield/internal/app"
	"github.com/jay94ks/seafield/internal/buildinfo"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/diskfs"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcimg"
	"github.com/jay94ks/seafield/internal/sfcp"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
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
	f := flag.NewFlagSet("sfcd", flag.ContinueOnError)
	f.SetOutput(diagnostic)
	var file onceString
	var version, check bool
	var engineAPI, engineSocket string
	f.Var(&file, "config", "node YAML file (required)")
	f.StringVar(&engineAPI, "engine-api", "", "development and tests: the engine API endpoint (unix:///…) instead of "+config.DefaultEngineAPI)
	f.StringVar(&engineSocket, "engine-socket", "", "development and tests: sfcd's engine socket path instead of "+sfcp.DefaultEngineSocket)
	f.BoolVar(&version, "version", false, "print version")
	f.BoolVar(&check, "check-config", false, "validate without opening node runtime resources")
	f.Usage = func() {
		fmt.Fprintln(diagnostic, "sfcd --config NODE.yaml run|check|engine-config [--output FILE|-]|init [options]|join [options]|recover [options]|restore [options]|set-listen|identity create|show DIR|diskfs serve SPEC|diskfs check CHUNK|adopt --plan FILE (offline source preparation)")
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
		fmt.Fprintln(out, buildinfo.Line("sfcd"))
		return 0
	}
	if len(args) == 3 && args[0] == "identity" && args[1] == "create" {
		// A new server (for example a VPS the cluster created) makes its
		// key with sfcd alone; it prints the public key.
		if check || file.set {
			return fail(diagnostic, errors.New("identity create takes no --config"), 2)
		}
		self, err := identity.Create(args[2])
		if err != nil {
			return fail(diagnostic, err, 1)
		}
		fmt.Fprintln(out, self.Actor())
		return 0
	}
	if len(args) == 3 && args[0] == "diskfs" && args[1] == "check" {
		// Reads one chunk file's headers and region map (testing aid).
		h, allocated, err := sfcimg.Check(args[2])
		if err != nil {
			return fail(diagnostic, err, 1)
		}
		fmt.Fprintf(out, "bundle=%x mode=%d grow=%t copy=%d index=%d start=%d length=%d allocated=%d generation=%d\n", h.Bundle, h.Mode, h.Grow, h.Copy, h.Index, h.Start, h.Length, allocated, h.Generation)
		return 0
	}
	if len(args) == 3 && args[0] == "diskfs" && args[1] == "serve" {
		// One fuse disk bundle's server process; sfcd itself starts it
		// (devel/design/node-disk-bundles.md §2-5).
		if check || file.set {
			return fail(diagnostic, errors.New("diskfs serve takes no --config"), 2)
		}
		if err := diskfs.Serve(args[2]); err != nil {
			return fail(diagnostic, err, 1)
		}
		return 0
	}
	if len(args) == 3 && args[0] == "identity" && args[1] == "show" {
		if check || file.set {
			return fail(diagnostic, errors.New("identity show takes no --config"), 2)
		}
		self, err := identity.Load(args[2])
		if err != nil {
			return fail(diagnostic, err, 1)
		}
		fmt.Fprintln(out, self.Actor())
		return 0
	}
	if len(args) > 0 && args[0] == "init" {
		if check {
			return fail(diagnostic, errors.New("init cannot be combined with check-config"), 2)
		}
		return runInit(args[1:], file.value, out, diagnostic)
	}
	if len(args) > 0 && args[0] == "recover" {
		if check {
			return fail(diagnostic, errors.New("recover cannot be combined with check-config"), 2)
		}
		return runRecover(args[1:], file.value, os.Stdin, out, diagnostic)
	}
	if len(args) > 0 && args[0] == "restore" {
		if check {
			return fail(diagnostic, errors.New("restore cannot be combined with check-config"), 2)
		}
		return runRestore(args[1:], file.value, os.Stdin, out, diagnostic)
	}
	if len(args) > 0 && args[0] == "set-listen" {
		if check {
			return fail(diagnostic, errors.New("set-listen cannot be combined with check-config"), 2)
		}
		return runSetListen(args[1:], file.value, out, diagnostic)
	}
	if len(args) > 0 && args[0] == "join" {
		if check {
			return fail(diagnostic, errors.New("join cannot be combined with check-config"), 2)
		}
		return runJoin(args[1:], file.value, out, diagnostic)
	}
	if len(args) > 0 && args[0] == "engine-config" {
		if check {
			return fail(diagnostic, errors.New("engine-config cannot be combined with check-config"), 2)
		}
		return runEngineConfig(args[1:], file.value, out, diagnostic)
	}
	if len(args) > 1 || len(args) == 1 && args[0] != "run" && args[0] != "check" {
		return fail(diagnostic, errors.New("usage: sfcd --config NODE.yaml run|check|init [options]|join [options]"), 2)
	}
	if file.value == "" {
		return fail(diagnostic, errors.New("--config is required"), 2)
	}
	c, err := config.LoadNode(file.value)
	if err != nil {
		return fail(diagnostic, err, 2)
	}
	if engineAPI != "" && (!strings.HasPrefix(engineAPI, "unix:///") || engineAPI == "unix:///") {
		return fail(diagnostic, errors.New("--engine-api must be an absolute unix:// endpoint"), 2)
	}
	if engineSocket != "" && (!filepath.IsAbs(engineSocket) || filepath.Clean(engineSocket) != engineSocket || engineSocket == "/") {
		return fail(diagnostic, errors.New("--engine-socket must be a clean absolute path"), 2)
	}
	c.EngineAPI, c.EngineSocket = engineAPI, engineSocket
	if check || len(args) == 1 && args[0] == "check" {
		if err = app.CheckClusterApps(c); err != nil {
			return fail(diagnostic, err, 2)
		}
		if err = checkEngine(c); err != nil {
			// The file itself is fine here; say so, so a check made while
			// the engine is stopped (as during an address move) is not read
			// as a bad node.yaml. Start sfed and check again.
			return fail(diagnostic, fmt.Errorf("node configuration is valid, but the engine cannot be reached (start sfed and check again): %w", err), 1)
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
			fmt.Fprintf(diagnostic, "sfcd installation failed before cleanup: %v\n", err)
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

	if err = runtime.ListenManagement(c); err != nil {
		_ = runtime.Close()
		return fail(diagnostic, err, 1)
	}
	if err = runtime.ListenEngine(c.EngineSocket); err != nil {
		_ = runtime.Close()
		return fail(diagnostic, fmt.Errorf("engine socket: %w", err), 1)
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
			if err = runtime.ListenManagement(c); err != nil {
				_ = runtime.Close()
				return fail(diagnostic, err, 1)
			}
			if err = runtime.ListenEngine(c.EngineSocket); err != nil {
				_ = runtime.Close()
				return fail(diagnostic, fmt.Errorf("engine socket: %w", err), 1)
			}
			continue
		case <-ctx.Done():
		case err = <-runtime.Engine().Failure():
			_ = runtime.Close()
			return fail(diagnostic, err, 70)
		}
		break
	}
	if ctx.Err() != nil {
		handOffLeadership(runtime.Engine(), diagnostic)
	}
	if err = runtime.Close(); err != nil {
		return fail(diagnostic, err, 1)
	}
	return 0
}

// handOffLeadership gives leadership away before a stop (SIGTERM, as a
// package upgrade sends), waiting at most 10 seconds; the stop goes on either
// way (devel/design/upgrades.md 3-5).
func handOffLeadership(e *cluster.Engine, diagnostic io.Writer) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	switch done, err := e.HandOffLeadership(ctx); {
	case err != nil:
		fmt.Fprintf(diagnostic, "sfcd stopping without a leadership hand-off: %v\n", err)
	case done:
		fmt.Fprintln(diagnostic, "sfcd handed leadership to another voter before stopping")
	}
}

func fail(out io.Writer, err error, code int) int { fmt.Fprintln(out, err); return code }

// checkEngine reaches the network module's engine and checks its version,
// so 'check' finds an engine that cannot serve managed bridges before run.
func checkEngine(c config.Node) error {
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
	d, err := engine.Open(ctx, c.EngineEndpoint(), "sfcd-check")
	if err != nil {
		return fmt.Errorf("network module engine %s: %w", c.EngineEndpoint(), err)
	}
	return d.Close()
}
