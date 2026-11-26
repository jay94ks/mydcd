// SPDX-License-Identifier: Apache-2.0

package membership

import (
	"bytes"
	"crypto/ed25519"
	"reflect"
	"testing"
)

func TestInvitationRequiresExplicitPinsAndBindsOriginalTarget(t *testing.T) {
	d, b, ak, bk := fixture(t)
	inv := Invitation{Schema: 1, Cluster: d.Cluster, Admin: [32]byte{90}, Genesis: d.Genesis, Source: d.Genesis, Target: b, JoinID: "join-b", ApprovalRevision: 2, MinimumIndex: 10}
	inv.Signature = ed25519.Sign(ak, InvitationBytes(inv))
	if inv.Verify(d.Cluster, memberKey(ak)) != nil {
		t.Fatal("valid pinned invitation rejected")
	}
	raw, err := inv.Encode()
	if err != nil {
		t.Fatal(err)
	}
	round, err := DecodeInvitation(raw)
	if err != nil || !reflect.DeepEqual(inv, round) {
		t.Fatal("canonical invitation", err)
	}
	for _, pins := range [][2][32]byte{{[32]byte{99}, memberKey(ak)}, {d.Cluster, memberKey(bk)}, {d.Cluster, {}}} {
		if inv.Verify(pins[0], pins[1]) == nil {
			t.Fatal("invitation self-authorized its pins")
		}
	}
	for _, mutate := range []func(*Invitation){func(i *Invitation) { i.Target.Key = d.Genesis.Key }, func(i *Invitation) { i.Target.Voter = true }, func(i *Invitation) { i.JoinID = "genesis" }, func(i *Invitation) { i.MinimumIndex = 0 }, func(i *Invitation) { i.Source.Endpoint = "LOCALHOST:8001" }, func(i *Invitation) { i.Target.ID = d.Genesis.ID }} {
		wrong := inv
		mutate(&wrong)
		wrong.Signature = ed25519.Sign(ak, InvitationBytes(wrong))
		if wrong.Verify(d.Cluster, memberKey(ak)) == nil {
			t.Fatal("invalid source/target scope accepted")
		}
	}
	tampered := inv
	tampered.JoinID = "different"
	if tampered.Verify(d.Cluster, memberKey(ak)) == nil {
		t.Fatal("signature did not bind join ID")
	}
	if _, err = DecodeInvitation(append(raw, ' ')); err == nil {
		t.Fatal("noncanonical invitation accepted")
	}
	if _, err = DecodeInvitation(bytes.Repeat([]byte("x"), 17<<10)); err == nil {
		t.Fatal("oversized invitation accepted")
	}
}
