// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"crypto/ed25519"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"
	"testing"
)

func TestRetirementExplicitReplayPreservesUnknownAndOriginalCommand(t *testing.T) {
	for _, phase := range []string{"drain", "proof", "delete"} {
		t.Run(phase, func(t *testing.T) {
			x := newInventoryFixture(t)
			x.all()
			x.keep(x.a.Retire(x.a.Revision(), x.f.c, "alice", "stop-original", "submitter", 1, nil, true))
			step := x.b.ReleaseOrder()[0]
			key := step.Key
			if phase != "drain" {
				x.phase(key, "drain")
				m, _ := x.a.Removal(key, "drain")
				c := x.a.d.Retirement.Targets[x.a.target(key)].Original
				owner := x.f.na
				if step.Owner == public(x.f.nb) {
					owner = x.f.nb
				}
				proof := ed25519.Sign(owner, schema.GoneBytes(x.f.cluster, key, c.Result.Generation, []byte(m.Command.Value)))
				x.keep(x.a.Gone(x.a.Revision(), key, proof))
				if phase == "delete" {
					x.phase(key, "proof")
				}
			}
			m, found := x.a.Removal(key, phase)
			if !found {
				t.Fatal("missing original", phase)
			}
			original := m.Command
			x.keep(x.a.SendRemoval(x.a.Revision(), x.f.c, "alice", key, phase))
			x.keep(x.a.UnknownRemoval(x.a.Revision(), key, phase))
			grant := func(expected uint64, actor, request string, digest [32]byte) (Inventory, error) {
				return x.a.AuthorizeRemovalReplay(expected, x.f.c, actor, key, phase, request, digest, x.shared)
			}
			if _, err := x.a.SendRemoval(x.a.Revision(), x.f.c, "alice", key, phase); err == nil {
				t.Fatal("unknown automatically dispatched")
			}
			missingLedger, _ := state.New("another-root")
			if _, err := x.a.AuthorizeRemovalReplay(x.a.Revision(), x.f.c, "alice", key, phase, "missing-ledger", state.Digest(original), missingLedger); err == nil {
				t.Fatal("missing original ledger identity authorized replay")
			}
			for _, bad := range []struct {
				revision uint64
				actor    string
				digest   [32]byte
			}{{x.a.Revision() - 1, "alice", state.Digest(original)}, {x.a.Revision(), "outsider", state.Digest(original)}, {x.a.Revision(), "alice", [32]byte{1}}} {
				if _, err := grant(bad.revision, bad.actor, "retry-original", bad.digest); err == nil {
					t.Fatal("bad replay grant accepted", bad)
				}
			}
			x.keep(grant(x.a.Revision(), "alice", "retry-original", state.Digest(original)))
			m, _ = x.a.Removal(key, phase)
			if m.Command != original || m.Journal.Pending.Phase != reconcile.RecoveryRequired || !m.Dispatchable() || m.Result != nil {
				t.Fatal("grant reset original Unknown")
			}
			if _, err := grant(x.a.Revision(), "alice", "another-grant", state.Digest(original)); err == nil {
				t.Fatal("unused authorization overwritten")
			}
			x.keep(x.a.SendRemoval(x.a.Revision(), x.f.c, "alice", key, phase))
			m, _ = x.a.Removal(key, phase)
			if m.Command != original || !m.Replay.Dispatched || m.Dispatchable() {
				t.Fatal("grant not consumed exactly once")
			}
			if _, err := x.a.SendRemoval(x.a.Revision(), x.f.c, "alice", key, phase); err == nil {
				t.Fatal("duplicate dispatch authorized")
			}
			if phase == "proof" {
				x.keep(x.a.UnknownRemoval(x.a.Revision(), key, phase))
				if _, err := grant(x.a.Revision(), "alice", "retry-original", state.Digest(original)); err == nil {
					t.Fatal("consumed authorization reused")
				}
				x.keep(grant(x.a.Revision(), "alice", "retry-explicit-second-attempt", state.Digest(original)))
				x.keep(x.a.SendRemoval(x.a.Revision(), x.f.c, "alice", key, phase))
			}
			first := x.apply(original)
			if first.Code != state.Applied {
				t.Fatal("original command not applied", first)
			}
			before := x.shared.Object(key)
			second := x.apply(original)
			if x.shared.Object(key) != before || second != first {
				t.Fatal("duplicate original Raft proposal changed effect")
			}
			x.keep(x.a.SettleRemoval(x.a.Revision(), key, phase, x.shared))
			m, _ = x.a.Removal(key, phase)
			if m.Result == nil || m.Result.Code != state.Applied || m.Command != original || m.Dispatchable() {
				t.Fatal("original result lost")
			}
		})
	}
}

func TestMutationLateOriginalResultWinsOverReplayAuthorization(t *testing.T) {
	x := newInventoryFixture(t)
	x.all()
	x.keep(x.a.Retire(x.a.Revision(), x.f.c, "alice", "stop-late", "submitter", 1, nil, true))
	key := x.b.ReleaseOrder()[0].Key
	m, _ := x.a.Removal(key, "drain")
	x.keep(x.a.SendRemoval(x.a.Revision(), x.f.c, "alice", key, "drain"))
	x.keep(x.a.UnknownRemoval(x.a.Revision(), key, "drain"))
	x.apply(m.Command)
	if _, err := x.a.AuthorizeRemovalReplay(x.a.Revision(), x.f.c, "alice", key, "drain", "retry-late", state.Digest(m.Command), x.shared); err == nil {
		t.Fatal("late committed result granted replay")
	}
	x.keep(x.a.SettleRemoval(x.a.Revision(), key, "drain", x.shared))
}
