// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/jay94ks/mydcd/internal/app"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/identity"
	"gopkg.in/yaml.v3"
)

func runInit(args []string, globalConfig string, out, diagnostic io.Writer) int {
	f := flag.NewFlagSet("mydcd init", flag.ContinueOnError)
	f.SetOutput(diagnostic)
	file := onceString{value: globalConfig, set: globalConfig != ""}
	var admin, request, clientOut onceString
	var timeout time.Duration
	f.Var(&file, "config", "managed node YAML file")
	f.Var(&admin, "admin-public-key", "explicit initial administrator enrollment public key")
	f.Var(&request, "request-id", "original init operation ID (repeat the SAME ID after interruption)")
	f.Var(&clientOut, "client-config-out", "write pinned user client YAML into an existing directory, without replacing another file")
	f.DurationVar(&timeout, "timeout", 30*time.Second, "initial Raft commit deadline")
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return fail(diagnostic, err, 2)
	}
	if f.NArg() != 0 || file.value == "" || admin.value == "" || request.value == "" || timeout <= 0 || timeout > 5*time.Minute {
		return fail(diagnostic, errors.New("init requires --config, --admin-public-key and --request-id; timeout must be in (0,5m]"), 2)
	}
	key, err := identity.ParseKey(admin.value)
	if err != nil || hex.EncodeToString(key[:]) != admin.value {
		return fail(diagnostic, errors.New("admin-public-key must be canonical lowercase Ed25519 public key"), 2)
	}
	c, err := config.LoadNode(file.value)
	if err != nil {
		return fail(diagnostic, err, 2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	initialized, err := app.Initialize(ctx, c, key, request.value)
	if err != nil {
		code := 1
		if errors.Is(err, context.DeadlineExceeded) {
			code = 4
		}
		return fail(diagnostic, err, code)
	}
	r := initialized.Installation
	if clientOut.value != "" {
		profile := struct {
			Version int           `yaml:"version"`
			Auth    string        `yaml:"auth"`
			Cluster string        `yaml:"cluster"`
			Peers   []config.Peer `yaml:"peers"`
		}{1, "user", hex.EncodeToString(r.Root.Cluster[:]), []config.Peer{r.Genesis}}
		raw, err := yaml.Marshal(profile)
		if err != nil {
			return fail(diagnostic, err, 1)
		}
		if err = writeClientProfile(clientOut.value, raw); err != nil {
			return fail(diagnostic, fmt.Errorf("node initialized; client profile output failed (reuse the same init request ID): %w", err), 1)
		}
	}
	status := "Initialized"
	if initialized.AwaitingAdmin {
		status = "AwaitingAdminEnrollment"
	}
	return printInit(out, diagnostic, map[string]any{"schema": 1, "status": status, "cluster": hex.EncodeToString(r.Root.Cluster[:]), "trust_root": hex.EncodeToString(r.Root.TrustRoot[:]), "node": r.Root.Self.ID, "node_key": hex.EncodeToString(r.Root.Self.Key[:]), "endpoint": r.Endpoint, "request": r.Root.Operation, "standalone": r.Root.Installed.Standalone(r.Root.Self.ID), "voters": r.Root.Installed.Voters(), "quorum": r.Root.Installed.Quorum(), "configuration_index": r.Root.Installed.Index, "applied_index": r.Root.AppliedIndex, "users": initialized.Users, "tenants": initialized.Tenants})
}

func printInit(out, diagnostic io.Writer, value any) int {
	if err := json.NewEncoder(out).Encode(value); err != nil {
		return fail(diagnostic, err, 1)
	}
	return 0
}

func writeClientProfile(path string, raw []byte) error {
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return errors.New("existing profile is not a private regular file")
		}
		previous, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !bytes.Equal(previous, raw) {
			return errors.New("refusing to replace a different client profile")
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	n, err := f.Write(raw)
	if err == nil && n != len(raw) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
