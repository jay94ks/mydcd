// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/reconcile"
)

// This finite fixture explores one cold move, one already-issued old permit,
// one new writer, and commit/cancel competing with delayed native observations.
// Only the fake native facts are modeled here; policy/ownership/gate transitions
// all call the same product functions that the real adapters will consume.
type world struct {
	s                      State
	from, to               Gate
	old                    Permit
	oldPin, newPin         Consumer
	fromRunning, toRunning bool
}

func worldKey(t *testing.T, w world) string {
	t.Helper()
	b, e := w.s.Encode()
	if e != nil {
		t.Fatal(e)
	}
	k, e := json.Marshal(struct {
		State                    json.RawMessage
		From, To                 GateCheckpoint
		FromPending, ToPending   *StartRequest
		FromSequence, ToSequence uint64
		Old, New                 Consumer
		FromRunning, ToRunning   bool
	}{b, w.from.Checkpoint(), w.to.Checkpoint(), w.from.pending, w.to.pending, w.from.next, w.to.next, w.oldPin, w.newPin, w.fromRunning, w.toRunning})
	if e != nil {
		t.Fatal(e)
	}
	return string(k)
}
func TestVolumeFiniteCommitCancelAndLatePermitInterleavings(t *testing.T) {
	f := makeFixture(t)
	pin := f.acquire("db", 1, true)
	g, e := NewGate(f.s.Scope(), f.source, [32]byte{1})
	if e != nil {
		t.Fatal(e)
	}
	g, r := gateRequest(t, g, pin, 1)
	old, e := f.s.PermitStart(f.c, "admin", r)
	if e != nil {
		t.Fatal(e)
	}
	f.prepare("move", f.target)
	target, e := NewGate(f.s.Scope(), f.target, [32]byte{2})
	if e != nil {
		t.Fatal(e)
	}
	initial := world{s: f.s, from: g, to: target, old: old, oldPin: pin, fromRunning: true}
	events := []string{"old-start", "old-settle", "stop-source", "release-source", "fence-gate", "report-fence", "manifest", "verify", "commit", "arm", "target-pin", "target-start", "target-settle", "active", "cleanup-source", "cleanup-target", "cancel", "target-gone", "finish-cancel"}
	step := func(w world, event string) (world, bool) {
		var err error
		m, _ := w.s.Move("move")
		switch event {
		case "old-start":
			w.from, err = w.from.Accept(w.old)
			if err == nil {
				w.fromRunning = true
			}
		case "old-settle":
			w.from, err = w.from.SettleStart(w.oldPin, reconcile.EffectApplied)
		case "stop-source":
			if w.from.d.Starting != nil || !w.fromRunning {
				return w, false
			}
			w.fromRunning = false
		case "release-source":
			if w.fromRunning || w.from.d.Starting != nil {
				return w, false
			}
			w.s, err = w.s.Release(f.gone(w.oldPin))
		case "fence-gate":
			w.from, err = w.from.Fence(m.Binding.SourceOwnerRevision)
		case "report-fence":
			if w.fromRunning || w.from.d.Starting != nil || w.from.d.FenceThrough < m.Binding.SourceOwnerRevision {
				return w, false
			}
			w.s, err = w.s.RecordFence(f.fence(m))
		case "manifest":
			w.s, err = w.s.BeginCopy(f.manifest(m, [32]byte{33}))
		case "verify":
			if m.Manifest == nil {
				return w, false
			}
			w.s, err = w.s.VerifyCopy(f.copy(m, *m.Manifest))
		case "commit":
			w.s, err = w.s.CommitOwner(f.c, "admin", "move", w.s.Revision(), m.Binding.SourceOwnerRevision)
		case "arm":
			w.s, err = w.s.Arm(f.c, "admin", "move", w.s.Revision())
		case "target-pin":
			w.s, w.newPin, err = w.s.Acquire(f.c, "admin", w.s.Revision(), "db", 2, true)
		case "target-start":
			if w.toRunning {
				return w, false
			}
			var req StartRequest
			w.to, req, err = w.to.Request(w.newPin, [32]byte{4})
			if err != nil {
				return w, false
			}
			var p Permit
			p, err = w.s.PermitStart(f.c, "admin", req)
			if err != nil {
				return w, false
			}
			w.to, err = w.to.Accept(p)
			if err == nil {
				w.toRunning = true
			}
		case "target-settle":
			w.to, err = w.to.SettleStart(w.newPin, reconcile.EffectApplied)
		case "active":
			if !w.toRunning || w.to.d.Starting != nil {
				return w, false
			}
			p := ActiveProof{Binding: m.Binding, Consumer: w.newPin, Running: true}
			p.Signature = ed25519.Sign(f.b, ActiveBytes(p))
			w.s, err = w.s.RecordActive(p)
		case "cleanup-source", "cleanup-target":
			owner := f.target
			k := f.b
			retained := false
			if event == "cleanup-source" {
				if w.fromRunning || w.from.d.FenceThrough < m.Binding.SourceOwnerRevision {
					return w, false
				}
				owner = f.source
				k = f.a
				retained = true
			}
			p := CleanupProof{Binding: m.Binding, Owner: owner, TransferClosed: true, RetainedFenced: retained}
			p.Signature = ed25519.Sign(k, CleanupBytes(p))
			w.s, err = w.s.RecordCleanup(p)
		case "cancel":
			w.s, err = w.s.Cancel(f.c, "admin", "move", w.s.Revision())
		case "target-gone":
			if w.toRunning || w.to.d.Starting != nil {
				return w, false
			}
			w.s, err = w.s.RecordCancelTarget(f.cancelProof(m))
		case "finish-cancel":
			w.s, err = w.s.FinishCancel(f.c, "admin", "move", w.s.Revision(), m.Binding.SourceOwnerRevision)
		}
		return w, err == nil
	}
	queue := []world{initial}
	seen := map[string]bool{worldKey(t, initial): true}
	edges := 0
	completed, cancelled, lateUnpinned := false, false, false
	for head := 0; head < len(queue); head++ {
		w := queue[head]
		if w.fromRunning && w.toRunning {
			t.Fatal("two active writers")
		}
		m, _ := w.s.Move("move")
		if w.toRunning && (!m.Irreversible || m.CommitRevision == 0 || w.from.d.FenceThrough < m.Binding.SourceOwnerRevision) {
			t.Fatal("target activation without original durable fence/irreversible marker")
		}
		completed = completed || m.Phase == Completed
		cancelled = cancelled || m.Phase == Cancelled
		lateUnpinned = lateUnpinned || w.fromRunning && w.s.consumerIndex(w.oldPin) < 0
		for _, event := range events {
			n, ok := step(w, event)
			if !ok {
				continue
			}
			edges++
			key := worldKey(t, n)
			if !seen[key] {
				seen[key] = true
				queue = append(queue, n)
			}
		}
		if len(queue) > 10000 {
			t.Fatal("fixture unexpectedly unbounded")
		}
	}
	if !completed || !cancelled || !lateUnpinned {
		t.Fatalf("missing branch: completed=%v cancelled=%v late-unpinned=%v", completed, cancelled, lateUnpinned)
	}
	t.Logf("explored %d distinct states, %d accepted edges; writer<=1", len(seen), edges)
}
