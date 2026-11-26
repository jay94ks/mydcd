// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

func TestMoveCancelOwnerFactsAtomicallyPreserveUnchangedSource(t *testing.T) {
	for _, sourceFirst := range []bool{true, false} {
		t.Run(map[bool]string{true: "source-first", false: "target-first"}[sourceFirst], func(t *testing.T) {
			f, q := moveCore(t)
			f.apply("live-writer", "acquire-volume", f.core().Revision(), VolumeAcquire{Scope: q.Scope, Consumer: "database", Generation: 1, Writable: true}, state.Applied)
			writer := f.core().Consumers()[0]
			f.apply("move", "begin-volume-move", f.core().Revision(), q, state.Applied)
			j, _, _ := f.view().Move(VolumeMoveSelection{Scope: q.Scope, ID: q.ID})
			f.apply("cancel", "cancel-volume-move", f.core().Revision(), j.Selection(), state.Applied)
			kinds := []string{"cancel-source", "cancel-target"}
			if !sourceFirst {
				kinds[0], kinds[1] = kinds[1], kinds[0]
			}
			for i, kind := range kinds {
				key, owner := f.node, j.Binding.Source
				if kind == "cancel-target" {
					key = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{124}, 32))
					owner = j.Binding.Target
				}
				permit, err := f.p.VolumeMovePermit(f.s, owner.Key, VolumeMovePermitRequest{Selection: j.Selection(), Kind: kind}, j.ExpiresAt+1)
				if err != nil || kind == "cancel-source" && !permit.SourceUnchanged {
					t.Fatal("original cancellation requires an unexpired start permission", err)
				}
				r := moveReport(t, f, kind)
				r.At = j.ExpiresAt + 1
				if kind == "cancel-source" {
					proof := volumes.CleanupProof{Binding: j.Binding, Owner: j.Binding.Source, TransferClosed: true, Unchanged: true}
					proof.Signature = ed25519.Sign(key, volumes.CleanupBytes(proof))
					r.Cleanup = &proof
				} else {
					proof := volumes.CancelProof{Binding: j.Binding, StagingGone: true, StartsSettled: true, MountsGone: true, TransferClosed: true}
					proof.Signature = ed25519.Sign(key, volumes.CancelBytes(proof))
					r.CancelledTarget = &proof
				}
				r.Signature = ed25519.Sign(key, VolumeMoveReportBytes(r))
				applyMoveOwnerReport(t, f, owner.Key, r, state.Applied)
				_, m, _ := f.view().Move(j.Selection())
				if i == 0 && m.Phase != volumes.Cancelling || i == 1 && m.Phase != volumes.Cancelled {
					t.Fatal("one-sided/non-atomic cancellation", m.Phase)
				}
			}
			owner, revision := f.core().Owner()
			if owner != j.Binding.Source || revision != j.Binding.SourceOwnerRevision || len(f.core().Consumers()) != 1 || f.core().Consumers()[0] != writer || f.core().CheckActivation(writer) != nil {
				t.Fatal("early cancellation replaced/retired the original running source")
			}
			raw, err := state.Encode(f.s)
			if err != nil {
				t.Fatal(err)
			}
			f.s, err = state.Decode(raw)
			if err != nil {
				t.Fatal(err)
			}
			_, restored, ok := f.view().Move(j.Selection())
			if !ok || restored.SourceCleanup == nil || !restored.SourceCleanup.Unchanged || restored.CancelledTarget == nil || restored.Fence != nil {
				t.Fatal("cancelled snapshot lost original evidence")
			}
		})
	}
}
