// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/reconcile"
	controlapi "github.com/moby/buildkit/api/services/control"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/grpc"
)

func cachePruneDaemonFixture(t *testing.T) (*nativeFixture, NativeCachePruneGrant, NativeCachePruneAuthority) {
	return cachePruneDaemonFixtureWithSpec(t, nil)
}

func cachePruneDaemonFixtureWithSpec(t *testing.T, edit func(*NativeCachePruneSpec)) (*nativeFixture, NativeCachePruneGrant, NativeCachePruneAuthority) {
	t.Helper()
	f := newNativeFixture(t, false)
	nativeCachePruneTestIdle(t, f)
	g := nativeCachePruneTestGrant(f, 90)
	if edit != nil {
		edit(&g.Spec)
	}
	if err := f.jobs.AcceptCachePrune(g); err != nil {
		t.Fatal(err)
	}
	g.Phase, g.Revision, g.Index = "running", 2, 11
	root := nativeTestRoot(t, f.spec)
	if err := f.jobs.ClaimCachePrune(g, int(root.Fd())); err != nil {
		t.Fatal(err)
	}
	authorize := func(context.Context, NativeCachePruneSpec, bool) (NativeCachePruneGrant, error) { return g, nil }
	if err := f.jobs.PrepareCachePruneWorkspace(f.ctx(), g.Spec, authorize); err != nil {
		t.Fatal(err)
	}
	identity, opts, err := planCachePrune(g.Spec, f.docker.Owner)
	if err != nil {
		t.Fatal(err)
	}
	f.edit(func() { f.plan.Container = identity; f.options = opts })
	return f, g, authorize
}
func cachePruneDaemonSDK(t *testing.T, f *nativeFixture, g NativeCachePruneGrant, server *cachePruneControlFixture) {
	t.Helper()
	dir, err := os.Open(filepath.Join(f.spec.Scope.Root.Path, cachePruneWorkspaceNames(g.Spec)[1]))
	if err != nil {
		t.Fatal(err)
	}
	socket := fmt.Sprintf("/proc/self/fd/%d/buildkit.sock", dir.Fd())
	listener, err := net.Listen("unix", socket)
	if err != nil {
		_ = dir.Close()
		t.Fatal(err)
	}
	if err := os.Chown(socket, nativeBuilderUID, nativeBuilderUID); err != nil {
		_ = listener.Close()
		_ = dir.Close()
		t.Fatal(err)
	}
	rpc := grpc.NewServer()
	controlapi.RegisterControlServer(rpc, server)
	go rpc.Serve(listener)
	t.Cleanup(func() { rpc.Stop(); _ = listener.Close(); _ = dir.Close() })
}

// The real SDK's guarded Unix HTTP and gRPC clients plus actual files/bbolt.
// Docker and shared authority are fixtures, not real daemon/kernel evidence.
func TestCachePruneDaemonUsesNoBuildInputsAndRecoversOnlyOriginalCreateStartRemove(t *testing.T) {
	f, g, authorize := cachePruneDaemonFixture(t)
	_, opts, err := planCachePrune(g.Spec, f.docker.Owner)
	if err != nil || opts.HostConfig.NetworkMode != "none" || len(opts.HostConfig.Mounts) != 2 || opts.Config.WorkingDir != "/" || opts.Config.Entrypoint[4] != fmt.Sprint(g.Spec.At+f.spec.Policy.Seconds) || strings.Contains(strings.Join(opts.Config.Cmd, " "), "dockerfile") {
		t.Fatal(opts, err)
	}
	for _, mount := range opts.HostConfig.Mounts {
		if mount.Target == "/input" {
			t.Fatal("old build inputs mounted")
		}
	}
	f.edit(func() { f.lostCreate = true })
	if err := f.jobs.CreateCachePrune(f.ctx(), g.Spec, authorize); err == nil {
		t.Fatal("lost response reported success")
	}
	if err := f.jobs.CreateCachePrune(f.ctx(), g.Spec, authorize); err != nil {
		t.Fatal("same original not adopted", err)
	}
	if f.count("POST /containers/create") != 1 {
		t.Fatal("replacement created")
	}
	f.edit(func() { f.lostStart = true })
	if err := f.jobs.StartCachePrune(f.ctx(), g.Spec, authorize); err == nil {
		t.Fatal("lost start reported success")
	}
	// This branch observes the SAME original running after a lost reply.
	// A still-created original must instead remain unknown, without replay.
	f.edit(func() {
		f.state = container.State{Status: container.StateRunning, Running: true, Pid: 123, StartedAt: "2026-11-22T00:00:01Z"}
	})
	if err := f.jobs.StartCachePrune(f.ctx(), g.Spec, authorize); err != nil {
		t.Fatal(err)
	}
	native := strings.Repeat("b", 64)
	if f.count("POST /containers/"+native+"/start") != 1 {
		t.Fatal("original started twice")
	}
	// Shutdown of the known original does not need a fresh quorum grant.
	denied := func(context.Context, NativeCachePruneSpec, bool) (NativeCachePruneGrant, error) {
		t.Fatal("cleanup requested new authority")
		return NativeCachePruneGrant{}, ErrConflict
	}
	if err := f.jobs.StopCachePrune(f.ctx(), g.Spec, denied, true); err != nil {
		t.Fatal(err)
	}
	f.edit(func() { f.lostRemove = true })
	if err := f.jobs.RemoveCachePrune(f.ctx(), g.Spec); err == nil {
		t.Fatal("lost remove reported success")
	}
	// The reply was lost, and a later inspect now positively reports this
	// original absent. Presence alone cannot authorize a second DELETE.
	f.edit(func() { f.exists = false })
	if err := f.jobs.RemoveCachePrune(f.ctx(), g.Spec); err != nil {
		t.Fatal(err)
	}
	if f.count("DELETE /containers/"+native) != 1 {
		t.Fatal("removal retransmitted")
	}
	row, err := f.jobs.CachePruneRecord(g.Spec)
	if err != nil || !row.Daemon.Effects.Removed || !row.Daemon.Effects.Waited {
		t.Fatal(row, err)
	}
}

func TestCachePruneDaemonReadinessIsNotDispatchAndUnknownRPCIsNotRetried(t *testing.T) {
	for _, mode := range []string{"", "partial", "foreign"} {
		t.Run(mode, func(t *testing.T) {
			f, g, authorize := cachePruneDaemonFixture(t)
			if err := f.jobs.CreateCachePrune(f.ctx(), g.Spec, authorize); err != nil {
				t.Fatal(err)
			}
			if err := f.jobs.StartCachePrune(f.ctx(), g.Spec, authorize); err != nil {
				t.Fatal(err)
			}
			if err := f.jobs.RunCachePrune(f.ctx(), g.Spec, authorize); !errors.Is(err, reconcile.ErrPending) {
				t.Fatal("missing socket became dispatch", err)
			}
			row, err := f.jobs.CachePruneRecord(g.Spec)
			if err != nil || row.RPC != nil {
				t.Fatal("readiness made Sent", row, err)
			}
			server := &cachePruneControlFixture{mode: mode, rows: map[string]*controlapi.UsageRecord{"one": {ID: "one", Size: 11}, "two": {ID: "two", Size: 12}, "busy": {ID: "busy", Size: 13, InUse: true}}}
			server.before = func(*controlapi.PruneRequest) {
				r, err := f.jobs.CachePruneRecord(g.Spec)
				if err != nil || r.RPC == nil || r.RPC.Code != "UNKNOWN" || r.RPC.SentAt == 0 {
					t.Error("SDK called before durable Sent", r, err)
				}
			}
			cachePruneDaemonSDK(t, f, g, server)
			runErr := f.jobs.RunCachePrune(f.ctx(), g.Spec, authorize)
			if (runErr == nil) != (mode == "") {
				t.Fatal(mode, runErr)
			}
			row, err = f.jobs.CachePruneRecord(g.Spec)
			if err != nil || row.RPC == nil || row.RPC.ReturnedAt == 0 || (row.RPC.Code == "OK") != (mode == "") {
				t.Fatal(row, err)
			}
			if len(server.requests) != 1 {
				t.Fatal("wrong RPC count", len(server.requests))
			}
			if err := f.jobs.RunCachePrune(f.ctx(), g.Spec, authorize); !errors.Is(err, ErrConflict) {
				t.Fatal("retained RPC retried", err)
			}
			if len(server.requests) != 1 {
				t.Fatal("unknown replayed")
			}
			raw, _ := json.Marshal(row)
			if strings.Contains(string(raw), "never-persist-raw") {
				t.Fatal("raw SDK error retained")
			}
			if err := f.jobs.StopCachePrune(f.ctx(), g.Spec, nil, true); err != nil {
				t.Fatal(err)
			}
			if err := f.jobs.RemoveCachePrune(f.ctx(), g.Spec); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type cachePruneFinishFailure struct {
	Transactions
	key  []byte
	fail bool
}

func (s *cachePruneFinishFailure) Update(edit func(*bolt.Tx) error) error {
	return s.Transactions.Update(func(tx *bolt.Tx) error {
		if err := edit(tx); err != nil {
			return err
		}
		var r NativeCachePruneRecord
		if s.fail && json.Unmarshal(tx.Bucket(nativeBucket).Get(s.key), &r) == nil && r.RPC != nil && r.RPC.ReturnedAt > 0 {
			return errors.New("injected completion commit failure")
		}
		return nil
	})
}
func TestCachePruneDaemonCompletionCommitLossKeepsSentWithoutReplayingSDK(t *testing.T) {
	f, g, authorize := cachePruneDaemonFixture(t)
	if err := f.jobs.CreateCachePrune(f.ctx(), g.Spec, authorize); err != nil {
		t.Fatal(err)
	}
	if err := f.jobs.StartCachePrune(f.ctx(), g.Spec, authorize); err != nil {
		t.Fatal(err)
	}
	server := &cachePruneControlFixture{rows: map[string]*controlapi.UsageRecord{"one": {ID: "one", Size: 11}}}
	cachePruneDaemonSDK(t, f, g, server)
	failing := &cachePruneFinishFailure{Transactions: f.db, key: nativeCachePruneKey(g.Spec.Intent), fail: true}
	f.jobs.db = failing
	if err := f.jobs.RunCachePrune(f.ctx(), g.Spec, authorize); err == nil {
		t.Fatal("failed completion committed")
	}
	failing.fail = false
	f.reopen()
	row, err := f.jobs.CachePruneRecord(g.Spec)
	if err != nil || row.RPC == nil || row.RPC.Code != "UNKNOWN" || row.RPC.ReturnedAt != 0 {
		t.Fatal("lost response fabricated success", row, err)
	}
	if err := f.jobs.RunCachePrune(f.ctx(), g.Spec, authorize); !errors.Is(err, ErrConflict) {
		t.Fatal("unknown replayed", err)
	}
	if len(server.requests) != 1 {
		t.Fatal(len(server.requests))
	}
	// Confirm the SDK client still observes the same original native ID.
	if _, err := f.docker.API.ContainerInspect(f.ctx(), strings.Repeat("b", 64), client.ContainerInspectOptions{}); err != nil {
		t.Fatal(err)
	}
}

func TestCachePruneDaemonEmptySelectionNeverSendsPruneAndRevocationBeforeSentIsRetained(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		t.Run(fmt.Sprint(revoke), func(t *testing.T) {
			f, g, authorize := cachePruneDaemonFixture(t)
			if err := f.jobs.CreateCachePrune(f.ctx(), g.Spec, authorize); err != nil {
				t.Fatal(err)
			}
			if err := f.jobs.StartCachePrune(f.ctx(), g.Spec, authorize); err != nil {
				t.Fatal(err)
			}
			rows := map[string]*controlapi.UsageRecord{"busy": {ID: "busy", Size: 13, InUse: true}}
			if revoke {
				rows["one"] = &controlapi.UsageRecord{ID: "one", Size: 11}
			}
			server := &cachePruneControlFixture{rows: rows}
			cachePruneDaemonSDK(t, f, g, server)
			calls := 0
			current := func(context.Context, NativeCachePruneSpec, bool) (NativeCachePruneGrant, error) {
				calls++
				copy := g
				if revoke && calls >= 2 {
					copy.Allowed = false
				}
				return copy, nil
			}
			err := f.jobs.RunCachePrune(f.ctx(), g.Spec, current)
			if revoke && !errors.Is(err, ErrConflict) || !revoke && err != nil {
				t.Fatal(revoke, err)
			}
			row, err := f.jobs.CachePruneRecord(g.Spec)
			if err != nil || revoke && row.RPC != nil || !revoke && (row.RPC == nil || row.RPC.Code != "SKIPPED" || row.RPC.SentAt != 0) {
				t.Fatal(row, err)
			}
			if len(server.requests) != 0 {
				t.Fatal("empty/revoked request sent SDK prune")
			}
		})
	}
}

func TestCachePruneDaemonMissingCreateResponseAndAbsentNameDoesNotRecreate(t *testing.T) {
	f, g, authorize := cachePruneDaemonFixture(t)
	f.edit(func() { f.lostCreate = true })
	if err := f.jobs.CreateCachePrune(f.ctx(), g.Spec, authorize); err == nil {
		t.Fatal("lost response reported success")
	}
	f.edit(func() { f.exists = false })
	if err := f.jobs.CreateCachePrune(f.ctx(), g.Spec, authorize); !errors.Is(err, reconcile.ErrPending) {
		t.Fatal("absence reconstructed original", err)
	}
	if f.count("POST /containers/create") != 1 {
		t.Fatal("replacement request created")
	}
}
