// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
)

func TestRealBoundaryManagedContainerObservation(t *testing.T) {
	runManagedAppOwner(t, true, false, false, true, managedAppContainerObserve, true)
}

func verifyManagedContainerObservation(t *testing.T, ctx context.Context, r *Runtime, root string, user userauth.Client, peer sfcp.Peer, session access.Session, p control.Policy, read func() cluster.View, change func(string, string, uint64, any)) []*Runtime {
	t.Helper()
	// Reopening the DB/native owner does not finish a Raft election. The test
	// requires an available control before expecting its first quorum read.
	ready := read()
	if ready.Local || ready.RaftIndex == 0 {
		t.Fatal("control quorum not ready after reopen")
	}
	query := func(label string, client userauth.Client, target sfcp.Peer) {
		t.Helper()
		t.Log("container observation path", label)
		for _, kind := range []string{"logs", "top", "stats", "inspect"} {
			q := containerops.Query{Schema: 1, Selection: containerops.Selection{App: "app", Service: "web"}, Kind: kind, MaxBytes: 16384}
			if kind == "logs" {
				q.Tail, q.Stdout, q.Stderr = 200, true, true
			}
			reply, err := client.ObserveContainer(ctx, target, session, "tenant", q)
			if err != nil || reply.Container == nil {
				// Inspect only this failed finite read; no new app/operation is sent.
				v, readErr := r.Engine().Read(ctx, false)
				if readErr != nil {
					t.Fatal("failed read diagnostic", err, readErr)
				}
				target, targetErr := p.ContainerTarget(v.State, session, time.Now().Unix(), "tenant", q)
				if targetErr != nil {
					apps, appsErr := p.ReadApps(v.State)
					t.Log("target derivation", targetErr, "apps decode", appsErr, "bindings", len(apps.Bindings().Live()))
					for _, b := range apps.Bindings().Live() {
						source, found := apps.BindingSource(b.Digest())
						t.Log("binding identity", b.Needs().Use.Tenant, b.Needs().Use.App, b.Needs().Use.Service, b.Needs().Use.Node, "source", found, source.Task)
					}
				} else {
					observed, cause := r.containerObservation(ctx, control.ContainerRead{Session: session, Query: q, Target: target})
					t.Log("native observation diagnostic", "call", cause, "result", observed.Validate(q, target))
				}
				t.Fatal("actual container query", label, kind, err)
			}
			got := reply.Container
			if got.Target.Owner != r.Identity.Public || got.Target.Instance != deployment.ResourceKey("task", "tenant", "app", "web") {
				t.Fatal("wrong native owner", got.Target)
			}
			switch kind {
			case "inspect":
				if got.Detail == nil || got.Detail.ImageID == "" || got.Detail.Name == "" || len(got.Detail.Environment) == 0 {
					t.Fatal("actual allowlisted Task detail unavailable")
				}
				for _, env := range got.Detail.Environment {
					if env.Source != "literal" && env.Value != nil {
						t.Fatal("native/image environment value returned in detail")
					}
				}
			case "logs":
				if !strings.Contains(string(got.Stdout), "sfc-observation-stdout") || !strings.Contains(string(got.Stderr), "sfc-observation-stderr") {
					t.Fatal("actual Docker streams not separated")
				}
			case "top":
				if len(got.Titles) == 0 || len(got.Processes) == 0 {
					t.Fatal("missing actual process list")
				}
			case "stats":
				if got.Stats == nil || got.Stats.MemoryLimitBytes == nil || *got.Stats.MemoryLimitBytes == 0 {
					t.Fatal("missing actual resource sample")
				}
			}
		}
		q := containerops.Query{Schema: 1, Selection: containerops.Selection{App: "app", Service: "web"}, Kind: "top", MaxBytes: 16384}
		if _, err := client.ObserveContainer(ctx, target, session, "foreign", q); err == nil {
			t.Fatal("foreign tenant accepted")
		}
		q.Selection.Instance = "unmanaged-container"
		if _, err := client.ObserveContainer(ctx, target, session, "tenant", q); err == nil {
			t.Fatal("arbitrary native target accepted")
		}
	}
	query("quic-owner", user, peer)
	// These are finite reads of the same original container, not a second app.
	for _, tc := range []struct {
		name   string
		mutate func(*containerops.Query)
		check  func(containerops.Result) bool
	}{
		{"stdout-only", func(q *containerops.Query) { q.Stderr = false }, func(v containerops.Result) bool {
			return strings.Contains(string(v.Stdout), "sfc-observation-stdout") && len(v.Stderr) == 0
		}},
		{"tail-timestamps", func(q *containerops.Query) { q.Tail = 1; q.Timestamps = true }, func(v containerops.Result) bool {
			lines := strings.FieldsFunc(string(v.Stdout)+string(v.Stderr), func(r rune) bool { return r == '\n' })
			if len(lines) == 0 || len(lines) > 2 {
				return false
			}
			for _, line := range lines {
				fields := strings.Fields(line)
				if len(fields) < 2 {
					return false
				}
				if _, err := time.Parse(time.RFC3339Nano, fields[0]); err != nil {
					return false
				}
			}
			return true
		}},
		{"since-future", func(q *containerops.Query) {
			q.Since = time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)
			q.Until = time.Now().Add(2 * time.Minute).UTC().Format(time.RFC3339Nano)
		}, func(v containerops.Result) bool { return len(v.Stdout)+len(v.Stderr) == 0 }},
		{"until-past", func(q *containerops.Query) { q.Until = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano) }, func(v containerops.Result) bool { return len(v.Stdout)+len(v.Stderr) == 0 }},
		{"bounded", func(q *containerops.Query) { q.MaxBytes = 1 }, func(v containerops.Result) bool { return v.Truncated && len(v.Stdout)+len(v.Stderr) == 1 }},
	} {
		q := containerops.Query{Schema: 1, Selection: containerops.Selection{App: "app", Service: "web"}, Kind: "logs", MaxBytes: 16384, Tail: 200, Stdout: true, Stderr: true}
		tc.mutate(&q)
		reply, err := user.ObserveContainer(ctx, peer, session, "tenant", q)
		if err != nil || reply.Container == nil || !tc.check(*reply.Container) {
			t.Fatal("actual Docker log option", tc.name, err)
		}
	}
	limited := session
	limited.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Deploy}}}
	limited.Signature = ed25519.Sign(r.Identity.Private, access.SessionBytes(limited))
	q := containerops.Query{Schema: 1, Selection: containerops.Selection{App: "app", Service: "web"}, Kind: "top", MaxBytes: 16384}
	if _, err := user.ObserveContainer(ctx, peer, limited, "tenant", q); err == nil {
		t.Fatal("actual scoped session bypassed missing Read")
	}
	unixPeer := peer
	unixPeer.Endpoint = "unix://" + filepath.Join(root, "observation.sock")
	if err := r.Mesh.ListenUnix(strings.TrimPrefix(unixPeer.Endpoint, "unix://")); err != nil {
		t.Fatal(err)
	}
	local := user
	var err error
	local.Mesh, err = sfcp.NewTransport(user.Self, user.Cluster, func(key sfcp.Identity) (sfcp.Peer, bool) { return unixPeer, key == unixPeer.Key })
	if err != nil {
		t.Fatal("Unix user transport", err)
	}
	defer local.Mesh.Close()
	local.Peers = []sfcp.Peer{unixPeer}
	query("unix-owner", local, unixPeer)
	// A real second control becomes leader while Docker stays on node-a.
	// This exercises User relay + owner Management read + fresh quorum permits.
	remote := prepareManagedHandoffControl(t, ctx, root, r, user, peer, session, p, read, change)
	if os.Getenv("SFC_TEST_RQ4_COMPACT_USER") == "1" || os.Getenv("SFC_TEST_RQ4_TUNNEL_USER") == "1" {
		return verifyManualCompactUserNative(t, ctx, r, remote, root, user, peer, session, p, change)
	}
	remotePeer, ok := r.Mesh.Peer(sfcp.Identity(remote.Identity.Public))
	if !ok {
		t.Fatal("new installed control missing")
	}
	if err := r.Engine().TransferLeadership(ctx, remotePeer.ID, remotePeer.Endpoint); err != nil {
		t.Fatal(err)
	}
	// SDK transfer completion is scheduling, not the target's elected state.
	leaderReady := func(owner *Runtime) error {
		for !owner.Engine().IsLeader() {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(20 * time.Millisecond):
			}
		}
		_, err := owner.Engine().Read(ctx, true)
		return err
	}
	if err := leaderReady(remote); err != nil {
		t.Fatal("remote elected control barrier", err)
	}
	defer func() {
		if err := remote.Engine().TransferLeadership(ctx, peer.ID, peer.Endpoint); err != nil {
			t.Error("restore fixture leadership", err)
			return
		}
		if err := leaderReady(r); err != nil {
			t.Error("restored elected control barrier", err)
		}
	}()
	query("quic-remote-owner", user, peer)
	if os.Getenv("SFC_TEST_RQ4_CACHE_USER") == "1" {
		verifyImageCacheUserNative(t, ctx, r, root, user, peer, session)
		return []*Runtime{remote}
	}
	// Reuse the fixture's real CLI wallet/profile after the same DB restart.
	for _, kind := range []string{"logs", "top", "stats", "inspect"} {
		args := []string{"compose", kind, "-p", "app", "web", "--tenant", "tenant", "--json"}
		if kind == "inspect" {
			args = append(args, "--max-bytes", "128")
		}
		out, diag, err := runManagedCLICommand(ctx, os.Getenv("SFC_TEST_CLI"), filepath.Join(root, "cli-home"), filepath.Join(root, "cli.yaml"), args, nil)
		if err != nil {
			t.Fatal("actual observation CLI", kind, err, string(diag))
		}
		var value containerops.Result
		if json.Unmarshal(out, &value) != nil || value.Kind != kind {
			t.Fatal("CLI observation format", fmt.Sprint(kind))
		}
	}
	verifyContainerDetailDrift(t, ctx, r, user, peer, session)
	verifyContainerLogPaging(t, ctx, r, user, peer, session)
	verifyUserTaskRestartNative(t, ctx, r, root, user, peer, session)
	return []*Runtime{remote}
}
