// SPDX-License-Identifier: Apache-2.0

package services

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/storage"
	"github.com/jay94ks/mydcd/internal/tenancy"
	"github.com/jay94ks/mydcd/internal/workload"
)

type dnsCrashNativeInput struct {
	Root, Path, Endpoint, Owner          string
	Key                                  []byte
	Catalog, Networks, Authority         json.RawMessage
	Config                               DNSConfig
	Bridge                               string
	BridgeGeneration                     uint64
	Roots                                []string
	MaxViews, MaxQueries, MaxConnections int
	IdleTimeout                          time.Duration
}

func TestRealBoundaryDNSCrashOwnedChild(t *testing.T) {
	path := os.Getenv("MYDC_DNS_CRASH_NATIVE_INPUT")
	if path == "" {
		t.Skip("owned child only")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var input dnsCrashNativeInput
	if err = json.Unmarshal(raw, &input); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	native, err := engine.Open(ctx, input.Endpoint, input.Owner)
	if err != nil {
		t.Fatal(err)
	}
	n, err := network.OpenManager(filepath.Join(input.Root, "network.db"), native)
	if err != nil {
		t.Fatal(err)
	}
	w, err := workload.OpenManager(filepath.Join(input.Root, "workload.db"), native, n)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := access.Decode(input.Catalog)
	if err != nil {
		t.Fatal(err)
	}
	networks, err := tenancy.Decode(input.Networks)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := DecodeAuthority(input.Authority)
	if err != nil {
		t.Fatal(err)
	}
	policy := DNSOwnerPolicy{Catalog: catalog, Networks: networks, Authority: authority, Actor: "admin", Config: input.Config, Bridge: input.Bridge, BridgeGeneration: input.BridgeGeneration, MaxConnections: input.MaxConnections}
	options := DNSOwnerOptions{Cluster: networks.Cluster(), Key: input.Key, Network: n, Workload: w, Roots: input.Roots, MaxViews: input.MaxViews, MaxQueries: input.MaxQueries, MaxConnections: input.MaxConnections, IdleTimeout: input.IdleTimeout,
		Current: func(context.Context, string, string) (DNSOwnerPolicy, error) { return policy, nil },
		Permit:  func(context.Context, DNSOwnerPolicy) error { return nil },
	}
	o, err := OpenDNSOwner(input.Path, options)
	if err != nil {
		t.Fatal(err)
	}
	if err = o.Apply(ctx, policy.Config.Tenant, policy.Config.ID); err != nil {
		t.Fatal(err)
	}
	if !o.Status(policy.Config.Tenant, policy.Config.ID).Ready {
		t.Fatal("child sockets not Ready")
	}
	_, _ = os.Stdout.WriteString("DNS_CRASH_NATIVE_READY\n")
	_, _ = os.Stdin.Read(make([]byte, 1))
	t.Fatal("owned child must be killed; no clean Close")
}

// Reuses the existing actual DNS/Bridge/Task fixture. Only these original
// manager handles are closed/reopened; the Task, Bridge and lease remain.
func crashNativeDNSOwner(t *testing.T, ctx context.Context, root, path string, native *engine.Client, n **network.Manager, w **workload.Manager, options *DNSOwnerOptions, query func()) *DNSOwner {
	t.Helper()
	policy, err := options.Current(ctx, "first", "dns")
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := policy.Catalog.Encode()
	if err != nil {
		t.Fatal(err)
	}
	networks, err := policy.Networks.Encode()
	if err != nil {
		t.Fatal(err)
	}
	authority, err := policy.Authority.Encode()
	if err != nil {
		t.Fatal(err)
	}
	input := dnsCrashNativeInput{root, path, native.API.DaemonHost(), native.Owner, options.Key, catalog, networks, authority, policy.Config, policy.Bridge, policy.BridgeGeneration, options.Roots, options.MaxViews, options.MaxQueries, options.MaxConnections, options.IdleTimeout}
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "dns-crash-child.json")
	if err = os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(file)
	if err = (*w).Close(); err != nil {
		t.Fatal(err)
	}
	*w = nil
	if err = (*n).Close(); err != nil {
		t.Fatal(err)
	}
	*n = nil
	reopen := func() error {
		if *n == nil {
			*n, err = network.OpenManager(filepath.Join(root, "network.db"), native)
			if err != nil {
				return err
			}
		}
		if *w == nil {
			*w, err = workload.OpenManager(filepath.Join(root, "workload.db"), native, *n)
			if err != nil {
				return err
			}
		}
		options.Network, options.Workload = *n, *w
		return nil
	}
	defer func() {
		if err := reopen(); err != nil {
			t.Error("restore original manager handles", err)
		}
	}()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRealBoundaryDNSCrashOwnedChild$", "-test.v")
	cmd.Env = append(os.Environ(), "MYDC_DNS_CRASH_NATIVE_INPUT="+file)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	ready := false
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		if scanner.Text() == "DNS_CRASH_NATIVE_READY" {
			ready = true
			break
		}
	}
	if !ready {
		t.Fatal("native child startup", scanner.Err(), stderr.String())
	}
	query() // actual approved container origin, UDP and TCP through child FDs
	if err = cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	err = cmd.Wait()
	waited = true
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.Success() {
		t.Fatal("original child must exit by SIGKILL", err)
	}
	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = db.Get("dns-owner")
	_ = db.Close()
	if err != nil {
		t.Fatal(err)
	}
	var disk dnsOwnerDisk
	if err = json.Unmarshal(raw, &disk); err != nil || disk.Stopped || disk.Process == nil || disk.Process.PID != cmd.Process.Pid {
		t.Fatal("original unclean process marker", err)
	}
	before, err := DecodeSettings(disk.Settings)
	if err != nil {
		t.Fatal(err)
	}
	if err = reopen(); err != nil {
		t.Fatal(err)
	}
	o, err := OpenDNSOwner(path, *options)
	if err != nil {
		t.Fatal("original native DB crash reopen", err)
	}
	for id, g := range before.groups {
		if !reflect.DeepEqual(g, o.settings.groups[id]) {
			_ = o.Close()
			t.Fatal("original group operation/pins changed")
		}
	}
	if len(o.dns.Queries()) != 0 || o.Status("first", "dns").Settings.Users != 0 {
		_ = o.Close()
		t.Fatal("paired crashed queries not settled")
	}
	t.Log("actual child serving UDP/TCP -> SIGKILL/Wait -> same DNS/network/workload DB and original Task/Bridge pin; current native permission still required")
	return o
}
