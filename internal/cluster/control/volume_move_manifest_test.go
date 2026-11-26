// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

func TestVolumeMoveManifestBindsArchiveAndRetainsOriginalReader(t *testing.T) {
	f, q := moveCore(t)
	f.apply("move", "begin-volume-move", f.core().Revision(), q, state.Applied)
	applyMoveReport(t, f, moveReport(t, f, "fenced"), state.Applied)
	applyMoveReport(t, f, moveReport(t, f, "reader"), state.Applied)
	j, _, _ := f.view().Move(VolumeMoveSelection{Scope: f.scope, ID: q.ID})
	receive := VolumeMovePermitRequest{Selection: j.Selection(), Kind: "receive"}
	if _, err := f.p.VolumeMovePermit(f.s, j.Binding.Target.Key, receive, 2); err == nil {
		t.Fatal("receive before original Manifest")
	}
	m := volumes.Manifest{Binding: j.Binding, Artifact: [32]byte{1}, Bytes: 4096, Files: 2, DataBytes: 17, ReadOnly: true}
	m.Signature = ed25519.Sign(f.node, volumes.ManifestBytes(m))
	r := moveReport(t, f, "reader")
	r.Kind = "manifest"
	r.Manifest = &m
	r.Signature = ed25519.Sign(f.node, VolumeMoveReportBytes(r))
	bad := m
	bad.DataBytes = 4097
	bad.Signature = ed25519.Sign(f.node, volumes.ManifestBytes(bad))
	r.Manifest = &bad
	r.Signature = ed25519.Sign(f.node, VolumeMoveReportBytes(r))
	raw, _ := json.Marshal(r)
	if _, err := f.p.ResolveVolumeMoveReport(f.s, j.Binding.Source.Key, raw); err == nil {
		t.Fatal("impossible archive receipt admitted")
	}
	r.Manifest = &m
	r.Signature = ed25519.Sign(f.node, VolumeMoveReportBytes(r))
	applyMoveReport(t, f, r, state.Applied)
	_, copy, ok := f.view().Move(j.Selection())
	if !ok || copy.Phase != volumes.Copying || copy.Manifest == nil || copy.Manifest.DataBytes != 17 || len(f.core().Consumers()) != 1 {
		t.Fatal("manifest erased source pin/bytes")
	}
	if _, err := f.p.VolumeMovePermit(f.s, j.Binding.Target.Key, receive, 2); err != nil {
		t.Fatal("exact target receive", err)
	}
	if _, err := f.p.VolumeMovePermit(f.s, j.Binding.Source.Key, receive, 2); err == nil {
		t.Fatal("source impersonated receiver")
	}
	if _, err := f.p.VolumeMovePermit(f.s, j.Binding.Target.Key, receive, j.ExpiresAt); err == nil {
		t.Fatal("receiver renewed original expiry")
	}
	catalog, err := f.p.Catalog(f.s)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := catalog.Tenant("tenant")
	f.apply("revoke-target", "set-nodes", tenant.Revision, NodeAssignment{Tenant: "tenant", Nodes: []string{"node-a"}}, state.Applied)
	if _, err := f.p.VolumeMovePermit(f.s, j.Binding.Target.Key, receive, 2); err == nil {
		t.Fatal("receiver bypassed current placement")
	}
	f.apply("cancel", "cancel-volume-move", f.core().Revision(), j.Selection(), state.Applied)
	if _, err := f.p.VolumeMovePermit(f.s, j.Binding.Target.Key, VolumeMovePermitRequest{Selection: j.Selection(), Kind: "receive-cleanup"}, j.ExpiresAt); err != nil {
		t.Fatal("target original cleanup lost after expiry/revoke", err)
	}
}
