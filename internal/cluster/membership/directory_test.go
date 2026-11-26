// SPDX-License-Identifier: Apache-2.0

package membership

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/reconcile"
)

func testPeer(id string, seed byte, voter bool) (config.Peer, ed25519.PrivateKey) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	return config.Peer{ID: id, Key: hex.EncodeToString(key.Public().(ed25519.PublicKey)), Endpoint: "127.0.0.1:" + map[string]string{"a": "8001", "b": "8002", "c": "8003"}[id], Voter: voter}, key
}
func memberKey(key ed25519.PrivateKey) [32]byte {
	var full [32]byte
	copy(full[:], key.Public().(ed25519.PublicKey))
	return full
}
func fixture(t *testing.T) (Directory, config.Peer, ed25519.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
	a, ak := testPeer("a", 21, true)
	b, bk := testPeer("b", 22, false)
	d, err := New([32]byte{71}, a)
	if err != nil {
		t.Fatal(err)
	}
	return d, b, ak, bk
}
func checked(t *testing.T, d Directory, err error) Directory {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := d.Encode()
	if err != nil {
		t.Fatal("output not valid", err)
	}
	round, err := Decode(raw)
	if err != nil || !reflect.DeepEqual(round, d) {
		t.Fatalf("round trip: %v", err)
	}
	return d
}
func invite(t *testing.T, d Directory, b config.Peer) Directory {
	t.Helper()
	n, err := d.Invite(b, "join-b")
	return checked(t, n, err)
}
func dispatch(t *testing.T, d Directory, id string, key ed25519.PrivateKey, index uint64) Directory {
	t.Helper()
	e, _ := d.Entry(id)
	n, err := d.Dispatch(id, e.Revision, e.Job.Pending.ID, index, memberKey(key))
	return checked(t, n, err)
}
func observe(t *testing.T, d Directory, id string, index uint64, actual config.Peer) Directory {
	t.Helper()
	e, _ := d.Entry(id)
	n, err := d.Observe(id, e.Revision, e.Job.Pending.ID, index, actual)
	return checked(t, n, err)
}
func installed(t *testing.T, d Directory, id string, key ed25519.PrivateKey, index uint64) Directory {
	t.Helper()
	e, _ := d.Entry(id)
	a := Ack{Schema: 1, Cluster: d.Cluster, Node: id, JoinID: e.JoinID, Key: memberKey(key), ConfigurationIndex: index, AppliedIndex: index + 1}
	a.Signature = ed25519.Sign(key, AckBytes(a))
	n, err := d.Installed(a, e.Revision)
	return checked(t, n, err)
}
func assertRejected(t *testing.T, before, after Directory, err error) {
	t.Helper()
	if err == nil || !reflect.DeepEqual(before, after) {
		t.Fatal("invalid transition changed state or succeeded", err)
	}
}

func TestMemberJoinInstallationAndExplicitPromotion(t *testing.T) {
	d, b, ak, bk := fixture(t)
	d = invite(t, d, b)
	if d.MemberKey(memberKey(bk)) || len(d.Issuers()) != 1 {
		t.Fatal("invitation grants member authority")
	}
	e, _ := d.Entry("b")
	n, err := d.Promote("b", e.Revision)
	assertRejected(t, d, n, err)
	d = dispatch(t, d, "b", ak, 10)
	d = observe(t, d, "b", 12, b)
	e, _ = d.Entry("b")
	if e.Phase != Learner || d.MemberKey(memberKey(bk)) {
		t.Fatal("native addition is not installation")
	}
	n, err = d.Promote("b", e.Revision)
	assertRejected(t, d, n, err)
	d = installed(t, d, "b", bk, 12)
	if !d.MemberKey(memberKey(bk)) || len(d.Issuers()) != 2 {
		t.Fatal("installed nonvoter must be member without being voter")
	}
	e, _ = d.Entry("b")
	if e.Peer.Voter {
		t.Fatal("implicit promotion")
	}
	n, err = d.Promote("b", e.Revision)
	d = checked(t, n, err)
	e, _ = d.Entry("b")
	if e.Job.Pending.Target != peerResource(config.Peer{ID: b.ID, Key: b.Key, Endpoint: b.Endpoint, Voter: true}) || e.Job.Pending.ID != 2 || e.Peer.Voter || !d.MemberKey(memberKey(bk)) {
		t.Fatal("promotion changed native state or lost authority")
	}
	d = dispatch(t, d, "b", ak, 15)
	b.Voter = true
	d = observe(t, d, "b", 18, b)
	e, _ = d.Entry("b")
	if e.Phase != Active || !e.Peer.Voter || e.Ack.ConfigurationIndex != 12 || e.Job.LastID != 2 {
		t.Fatal("promotion lost original install proof")
	}
	n, err = d.Promote("b", e.Revision)
	assertRejected(t, d, n, err)
}
func TestMemberUnknownRetainsOriginalAndSerializesNativeChanges(t *testing.T) {
	d, b, ak, _ := fixture(t)
	d = invite(t, d, b)
	c, _ := testPeer("c", 23, false)
	n, err := d.Invite(c, "join-c")
	d = checked(t, n, err)
	d = dispatch(t, d, "b", ak, 7)
	e, _ := d.Entry("b")
	original := *e.Job.Pending
	n, err = d.Unknown("b", e.Revision, original.ID)
	d = checked(t, n, err)
	e, _ = d.Entry("b")
	if e.Job.Pending.Phase != reconcile.RecoveryRequired || e.BaseIndex != 7 || e.Job.Pending.Target != original.Target {
		t.Fatal("unknown lost original")
	}
	cEntry, _ := d.Entry("c")
	n, err = d.Dispatch("c", cEntry.Revision, cEntry.Job.Pending.ID, 9, memberKey(ak))
	assertRejected(t, d, n, err)
	n, err = d.Dispatch("b", e.Revision, original.ID, 9, memberKey(ak))
	assertRejected(t, d, n, err)
	for _, actual := range []config.Peer{c, {ID: b.ID, Key: b.Key, Endpoint: b.Endpoint, Voter: true}, {ID: b.ID, Key: b.Key, Endpoint: "127.0.0.1:9000"}} {
		n, err = d.Observe("b", e.Revision, original.ID, 12, actual)
		assertRejected(t, d, n, err)
	}
	n, err = d.Observe("b", e.Revision, original.ID, 7, b)
	assertRejected(t, d, n, err)
	d = observe(t, d, "b", 12, b) // Late positive evidence settles the same operation.
	d = dispatch(t, d, "c", ak, 12)
	if e, _ := d.Entry("c"); e.Job.Pending.Phase != reconcile.Dispatched {
		t.Fatal("serialized job cannot progress")
	}
}
func TestMemberCollisionCASAndCanonicalEndpoint(t *testing.T) {
	d, b, ak, bk := fixture(t)
	d = invite(t, d, b)
	c, _ := testPeer("c", 23, false)
	for _, p := range []config.Peer{b, {ID: c.ID, Key: b.Key, Endpoint: c.Endpoint}, {ID: c.ID, Key: c.Key, Endpoint: b.Endpoint}, {ID: c.ID, Key: c.Key, Endpoint: "127.0.0.1:08003"}, {ID: c.ID, Key: c.Key, Endpoint: "[::ffff:127.0.0.1]:8003"}, {ID: c.ID, Key: c.Key, Endpoint: "LOCALHOST:8003"}, {ID: c.ID, Key: c.Key, Endpoint: "localhost.:8003"}, {ID: c.ID, Key: c.Key, Endpoint: strings.Repeat("a", 321) + ":8003"}} {
		n, err := d.Invite(p, "join-c")
		assertRejected(t, d, n, err)
	}
	n, err := d.Invite(c, "join-b")
	assertRejected(t, d, n, err)
	e, _ := d.Entry("b")
	n, err = d.Dispatch("b", e.Revision-1, 1, 10, memberKey(ak))
	assertRejected(t, d, n, err)
	n, err = d.Dispatch("b", e.Revision, 1, 10, memberKey(bk))
	assertRejected(t, d, n, err)
	n, err = d.Dispatch("b", e.Revision, 2, 10, memberKey(ak))
	assertRejected(t, d, n, err)
	d.Revision = math.MaxUint64
	n, err = d.Invite(c, "join-c")
	assertRejected(t, d, n, err)
}
func TestMemberInstallationProofRejectsWrongScopeOrFloor(t *testing.T) {
	d, b, ak, bk := fixture(t)
	d = observe(t, dispatch(t, invite(t, d, b), "b", ak, 10), "b", 12, b)
	e, _ := d.Entry("b")
	base := Ack{Schema: 1, Cluster: d.Cluster, Node: "b", JoinID: "join-b", Key: memberKey(bk), ConfigurationIndex: 12, AppliedIndex: 13}
	changes := []func(*Ack){func(a *Ack) { a.Schema = 2 }, func(a *Ack) { a.Cluster[0]++ }, func(a *Ack) { a.Node = "a" }, func(a *Ack) { a.JoinID = "other" }, func(a *Ack) { a.Key = memberKey(ak) }, func(a *Ack) { a.ConfigurationIndex = 11 }, func(a *Ack) { a.AppliedIndex = 11 }}
	for i, change := range changes {
		a := base
		change(&a)
		a.Signature = ed25519.Sign(bk, AckBytes(a))
		n, err := d.Installed(a, e.Revision)
		assertRejected(t, d, n, err)
		t.Log("rejected scoped proof", i)
	}
	a := base
	a.Signature = ed25519.Sign(ak, AckBytes(a))
	n, err := d.Installed(a, e.Revision)
	assertRejected(t, d, n, err)
	a = base
	a.Signature = ed25519.Sign(bk, AckBytes(a))
	n, err = d.Installed(a, e.Revision-1)
	assertRejected(t, d, n, err)
	d = installed(t, d, "b", bk, 13)
	e, _ = d.Entry("b")
	n, err = d.Promote("b", e.Revision)
	d = checked(t, n, err)
	e, _ = d.Entry("b")
	n, err = d.Dispatch("b", e.Revision, e.Job.Pending.ID, 12, memberKey(ak))
	assertRejected(t, d, n, err)
}
func TestMemberRestoredJournalMustMatchRoleAndOriginalTarget(t *testing.T) {
	initial, b, ak, bk := fixture(t)
	stages := []Directory{initial}
	d := invite(t, initial, b)
	stages = append(stages, d)
	d = dispatch(t, d, "b", ak, 10)
	stages = append(stages, d)
	d = observe(t, d, "b", 12, b)
	stages = append(stages, d)
	d = installed(t, d, "b", bk, 12)
	stages = append(stages, d)
	e, _ := d.Entry("b")
	n, err := d.Promote("b", e.Revision)
	d = checked(t, n, err)
	stages = append(stages, d)
	d = dispatch(t, d, "b", ak, 14)
	stages = append(stages, d)
	b.Voter = true
	d = observe(t, d, "b", 17, b)
	stages = append(stages, d)
	for i, s := range stages {
		raw, _ := s.Encode()
		if _, err := Decode(append(raw, ' ')); err == nil {
			t.Fatal("noncanonical restore accepted")
		}
		if i == 0 {
			continue
		}
		for _, mutate := range []func(*Entry){func(e *Entry) { e.Peer.Endpoint = "127.0.0.1:9000" }, func(e *Entry) { e.Job.Desired.Spec = "wrong" }, func(e *Entry) { e.Job.Stopped = true }, func(e *Entry) { e.Job.GenerationFloor = 2 }, func(e *Entry) { e.Job.LastID++ }} {
			bad := clone(s)
			mutate(&bad.Entries[1])
			raw, _ := json.Marshal(bad)
			if _, err := Decode(raw); err == nil {
				t.Fatalf("tampered checkpoint accepted at phase %s", bad.Entries[1].Phase)
			}
		}
		entry, _ := s.Entry("b")
		if entry.Job.Pending != nil {
			entry.Job.Pending.Target.Spec = "alias"
		}
		if entry.Ack != nil {
			entry.Ack.Signature[0]++
		}
		if s.Validate() != nil {
			t.Fatal("Entry aliases source")
		}
	}
	// The returned transition must also detach the caller's signed ACK bytes.
	learner := stages[3]
	e, _ = learner.Entry("b")
	a := Ack{Schema: 1, Cluster: learner.Cluster, Node: "b", JoinID: e.JoinID, Key: memberKey(bk), ConfigurationIndex: 12, AppliedIndex: 13}
	a.Signature = ed25519.Sign(bk, AckBytes(a))
	n, err = learner.Installed(a, e.Revision)
	n = checked(t, n, err)
	a.Signature[0]++
	if n.Validate() != nil {
		t.Fatal("Installed retained mutable caller signature")
	}
}
