// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/identity"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
)

func stagedCheckerIntent(t *testing.T) (string, Client, access.Session, *identity.Identity, CheckerScriptIntent) {
	t.Helper()
	home, c, session, issuer := journalFixture(t)
	data := append([]byte("package checker\n"), bytes.Repeat([]byte("// frozen original source\n"), 4000)...)
	d := checker.SourceDescriptor{Tenant: "tenant", Digest: sha256.Sum256(data), Length: uint64(len(data)), SDK: 1}
	i, err := StageCheckerScript(home, c, session, "checker/original", "Ready_File", c.Peers[0], d, data, 7)
	if err != nil {
		t.Fatal(err)
	}
	return home, c, session, issuer, i
}

func TestCheckerIntentLargeSourceImmutableSignatureAndRelogin(t *testing.T) {
	home, c, session, issuer, original := stagedCheckerIntent(t)
	if len(original.Data) <= 65536 {
		t.Fatal("fixture did not cross existing metadata budget")
	}
	if _, err := json.Marshal(original); err == nil || fmt.Sprintf("%+v", original) != "[redacted lifecycle source intent]" {
		t.Fatal("ordinary encoding leaked source intent")
	}
	loaded, err := LoadCheckerScript(home, c, session, original.ID)
	if err != nil || !bytes.Equal(loaded.Data, original.Data) || !bytes.Equal(loaded.Signature, original.Signature) {
		t.Fatal("private source readback", err)
	}
	newSelf, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(newSelf.Private)
	c.Self = newSelf
	current := session
	current.ID, current.Key = "relogin", newSelf.Public
	current.Signature = ed25519.Sign(issuer.Private, access.SessionBytes(current))
	loaded, err = LoadCheckerScript(home, c, current, original.ID)
	if err != nil || loaded.Initiator.Key != session.Key || !bytes.Equal(loaded.Signature, original.Signature) {
		t.Fatal("relogin replaced original provenance", err)
	}
	for _, mutate := range []func(*CheckerScriptIntent){
		func(i *CheckerScriptIntent) { i.Name = "changed" },
		func(i *CheckerScriptIntent) { i.Expected++ },
		func(i *CheckerScriptIntent) { i.Provider.Endpoint = "127.0.0.1:8443" },
		func(i *CheckerScriptIntent) { i.Data = []byte("replacement") },
		func(i *CheckerScriptIntent) {
			i.Descriptor.Modules = []checker.ModulePin{{Path: "example.invalid/changed", Version: "v1.0.0", Length: 1, Digest: [32]byte{1}}}
		},
	} {
		next := loaded
		mutate(&next)
		if err := ReplaceCheckerScript(home, c, current, loaded, next); err == nil {
			t.Fatal("mutable source intent rebound")
		}
	}
}

func TestCheckerIntentConcurrentBeforeSendCASAndFactPin(t *testing.T) {
	home, c, session, issuer, original := stagedCheckerIntent(t)
	next := original
	next.Sequence = 1
	var group sync.WaitGroup
	results := make(chan error, 8)
	for range 8 {
		group.Add(1)
		go func() { defer group.Done(); results <- ReplaceCheckerScript(home, c, session, original, next) }()
	}
	group.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		} else if !errors.Is(err, ErrPrivateState) {
			t.Fatal(err)
		}
	}
	if success != 1 {
		t.Fatal("multiple source sends crossed original CAS", success)
	}
	actual, err := LoadCheckerScript(home, c, session, original.ID)
	if err != nil || actual.Sequence != 1 {
		t.Fatal("before-send floor not durable", err)
	}
	fact := checker.SourceFact{Upload: c.WithCheckerUpload(actual).checkerUpload, Schema: 1, Cluster: c.Cluster, Owner: issuer.Public, Tenant: actual.Tenant, SDK: 1, Digest: actual.Descriptor.Digest, Length: actual.Descriptor.Length}
	fact.Signature = ed25519.Sign(issuer.Private, checker.SourceFactBytes(fact))
	next = actual
	next.Fact = &fact
	if err := ReplaceCheckerScript(home, c, session, actual, next); err != nil {
		t.Fatal("original fact pin", err)
	}
	actual = next
	next.Sequence++
	if err := ReplaceCheckerScript(home, c, session, actual, next); err == nil {
		t.Fatal("retransmission after fact publication allowed")
	}
	next = actual
	next.Fact = nil
	if err := ReplaceCheckerScript(home, c, session, actual, next); err == nil {
		t.Fatal("original fact cleared")
	}
}

func TestCheckerIntentMovedEndpointKeepsNamespaceAndCurrentTrust(t *testing.T) {
	home, original, session, _, intent := stagedCheckerIntent(t)
	current := original
	current.Peers = append(current.Peers[:0:0], original.Peers...)
	current.Peers[0].Endpoint = "127.0.0.1:8443"
	// The namespace is the cluster: a moved endpoint keeps the original.
	if _, err := LoadCheckerScript(home, current, session, intent.ID); err != nil {
		t.Fatal("moved endpoint lost the original", err)
	}
	if peer, err := CheckerProviderPeer(current, intent.Provider); err != nil || peer.Endpoint != current.Peers[0].Endpoint || peer.Endpoint == intent.Provider.Endpoint {
		t.Fatal("same trusted provider did not use its current location", err)
	}
	changedKey := current
	changedKey.Peers = append(changedKey.Peers[:0:0], current.Peers...)
	changedKey.Peers[0].Key[0] ^= 1
	if _, err := CheckerProviderPeer(changedKey, intent.Provider); err == nil {
		t.Fatal("original namespace reapproved removed provider key")
	}
}

func TestCheckerIntentRegistrationUsesExistingImmutableOperationJournal(t *testing.T) {
	home, c, session, issuer, intent := stagedCheckerIntent(t)
	next := intent
	next.Sequence = 1
	if err := ReplaceCheckerScript(home, c, session, intent, next); err != nil {
		t.Fatal(err)
	}
	intent = next
	fact := checker.SourceFact{Upload: c.WithCheckerUpload(intent).checkerUpload, Schema: 1, Cluster: c.Cluster, Owner: issuer.Public, Tenant: intent.Tenant, SDK: 1, Digest: intent.Descriptor.Digest, Length: intent.Descriptor.Length}
	fact.Signature = ed25519.Sign(issuer.Private, checker.SourceFactBytes(fact))
	next.Fact = &fact
	if err := ReplaceCheckerScript(home, c, session, intent, next); err != nil {
		t.Fatal(err)
	}
	intent = next
	payload, _ := json.Marshal(control.LifecycleScriptPut{Tenant: intent.Tenant, Name: intent.Name, Source: fact})
	op := control.UserOperation{Schema: 1, Session: session, At: session.IssuedAt, Epoch: 4, RootRevision: 21, RequestID: intent.ID, Change: control.Change{Schema: 1, Principal: session.User, Action: "put-lifecycle-script", Expected: intent.Expected, Payload: payload}}
	op.Signature = ed25519.Sign(c.Self.Private, control.OperationBytes(op))
	if !CheckerRegistrationMatches(intent, op) {
		t.Fatal("first original registration mismatch")
	}
	if _, err := StageOperation(home, c, op); err != nil {
		t.Fatal(err)
	}
	changed := op
	changed.RootRevision++
	changed.Signature = ed25519.Sign(c.Self.Private, control.OperationBytes(changed))
	if _, err := StageOperation(home, c, changed); err == nil {
		t.Fatal("registration rebased original root CAS")
	}
	record, err := LoadOperation(home, c, session, op.RequestID)
	if err != nil || !sameOperation(record.Operation, op) {
		t.Fatal("original registration lost", err)
	}
}
