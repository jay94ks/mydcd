// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

func TestRetainedDeleteRequiresExactNativeGoneBeforeReleasingPhysicalBudget(t *testing.T) {
	f, job, _ := completedMoveCore(t)
	reader := f.session
	reader.Scopes = []access.Scope{{Tenant: f.scope.Tenant, Actions: []access.Action{access.Read}}}
	reader.Signature = ed25519.Sign(f.node, access.SessionBytes(reader))
	query := PublicReadQuery{App: f.scope.App, Name: f.scope.ID}
	assertPublic := func(status string) {
		t.Helper()
		page, err := f.p.PublicRead(f.s, reader, 10, "volume-retained-sources", f.scope.Tenant, query, "")
		if err != nil || len(page.Rows) != 1 || page.Rows[0].Retained == nil {
			t.Fatal("original retained source public row", page, err)
		}
		row := page.Rows[0].Retained
		if row.Move != job.Binding.ID || row.Node != job.Binding.Source.Node || row.Scope != job.Binding.Scope || row.State != status {
			t.Fatal("original retained identity/phase", row, status)
		}
		if _, err = f.p.PublicRead(f.s, reader, 10, "volume-retained-sources", "foreign", query, ""); !errors.Is(err, access.ErrDenied) {
			t.Fatal("retained source foreign tenant disclosed", err)
		}
	}
	assertPublic("retained")
	digest := job.Digest()
	writer := f.core().Consumers()[0]
	q := job.Selection()
	f.apply("delete-obsolete-source", "delete-retained-volume", f.core().Revision(), q, state.Applied)
	assertPublic("deleting")
	work, err := f.p.VolumeRetainedDeletePermit(f.s, job.Source.Owner.Key, q)
	if err != nil || work.Retained != q.ID || work.Native.Spec != job.Source.Spec || work.Native.Generation != job.Source.Generation {
		t.Fatal("delete work lost immutable physical source", err)
	}
	if _, err = f.p.VolumeRetainedDeletePermit(f.s, job.Binding.Target.Key, q); err == nil {
		t.Fatal("target member obtained obsolete source deletion work")
	}
	holds, err := f.view().originalHolds(f.s)
	if err != nil || len(holds) != 2 || len(f.core().Retained()) != 1 || f.core().CheckActivation(writer) != nil {
		t.Fatal("pending deletion released storage/current writer", err)
	}
	f.apply("replace-obsolete-deletion", "delete-retained-volume", f.core().Revision(), q, state.ConditionFailed)
	proof := volumes.NativeRemoved{Schema: 1, Scope: q.Scope, Owner: work.Native.Owner, Key: volumes.NativeKey(work.Native.Spec), Generation: work.Native.Generation, DeleteRevision: work.Revision}
	for _, scenario := range []string{"generation", "key", "move", "current-delete"} {
		bad := proof
		retained := q.ID
		switch scenario {
		case "generation":
			bad.Generation++
		case "key":
			bad.Key += "/other"
		case "move":
			retained = "another-move"
		case "current-delete":
			retained = ""
		}
		bad.Signature = ed25519.Sign(f.node, volumes.NativeRemovedBytes(bad))
		raw, _ := json.Marshal(VolumeDeleteReport{Schema: 1, Operation: "delete", Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(VolumesKey).Revision, At: 2, Proof: bad, Retained: retained})
		if _, err = f.p.ResolveVolumeDeleteReport(f.s, work.Native.Owner.Key, raw); err == nil {
			t.Fatal("wrong original native/move admitted", scenario)
		}
	}
	proof.Signature = ed25519.Sign(f.node, volumes.NativeRemovedBytes(proof))
	raw, _ := json.Marshal(VolumeDeleteReport{Schema: 1, Operation: "delete", Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(VolumesKey).Revision, At: 2, Proof: proof, Retained: q.ID})
	cmd, err := f.p.ResolveVolumeDeleteReport(f.s, work.Native.Owner.Key, raw)
	if err != nil {
		t.Fatal(err)
	}
	next, result, err := state.ApplyAdmitted(f.s, f.s.Index()+1, cmd, f.p.Validate, f.p.Reduce, f.p.AdmitModule)
	if err != nil || result.Code != state.Applied {
		t.Fatal("native deletion fact not committed", result.Code, err)
	}
	f.s = next
	assertPublic("removed")
	current, m, ok := f.view().Move(q)
	holds, err = f.view().originalHolds(f.s)
	if !ok || current.Digest() != digest || m.SourceDeletion == nil || m.SourceDeletion.Gone == nil || m.Phase != volumes.Completed || len(f.core().Retained()) != 0 || len(holds) != 1 || err != nil || f.core().CheckActivation(writer) != nil {
		t.Fatal("native Gone did not settle only the old physical hold", err)
	}
	encoded, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	f.s, err = state.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.p.Volumes(f.s); err != nil {
		t.Fatal("original intent/native tombstone lost in Snapshot", err)
	}
	assertPublic("removed")
	v := f.view()
	entry := v.entries[volumeKey(q.Scope)]
	delete(entry.RetainedDeletes, q.ID)
	v.entries[volumeKey(q.Scope)] = entry
	if f.p.validateVolumeDeletions(v) == nil {
		t.Fatal("native tombstone survived without its original signed deletion intent")
	}
}

func TestRetainedDeletePendingPreventsQuiescentWithoutBlockingCurrentReadiness(t *testing.T) {
	f, job, target := completedMoveCore(t)
	writer := f.core().Consumers()[0]
	gone := volumes.Gone{Scope: f.scope, Consumer: writer, Stopped: true, MountsGone: true}
	gone.Signature = ed25519.Sign(target, volumes.GoneBytes(gone))
	f.apply("release-finished-target", "release-volume", f.core().Revision(), gone, state.Applied)
	if !f.view().Quiescent() {
		t.Fatal("completed move with retained source should have no outstanding work")
	}
	f.apply("delete-retained-work", "delete-retained-volume", f.core().Revision(), job.Selection(), state.Applied)
	if f.view().Quiescent() || len(f.view().Deletions()) != 1 {
		t.Fatal("pending old-source deletion disappeared from current work")
	}
	current, ok := f.view().Native(f.scope.Tenant, f.scope.App, f.scope.ID)
	if !ok || current.Owner != job.Binding.Target || f.core().Deleting() {
		t.Fatal("old-source deletion marked current Volume unavailable/deleting")
	}
}
