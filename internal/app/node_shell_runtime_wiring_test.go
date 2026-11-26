// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/nodeshell"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/storage"
)

// The owner has already authenticated the current node before this private
// receipt read. Exercise original-store selection and current report signing,
// not a second authorization path or a claim of an actual SSH/native rotation.
func TestNodeShellRecoveryKeepsOriginalStoreAndUsesCurrentSigner(t *testing.T) {
	row, receipt, view, old := nodeShellObservationFixture()
	middle := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{21}, 32))
	next := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{22}, 32))
	root := t.TempDir()
	open := func(name string) *storage.DB {
		t.Helper()
		db, err := storage.Open(filepath.Join(root, name+".db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		return db
	}
	originalDB, middleDB, currentDB := open("original"), open("middle"), open("current")
	if err := saveNodeShellReceipt(originalDB, receipt); err != nil {
		t.Fatal(err)
	}
	runtime := &Runtime{Identity: &identity.Identity{Public: [32]byte(next.Public().(ed25519.PublicKey)), Private: next}, controlPolicy: control.Policy{Cluster: receipt.Cluster}, reports: currentDB, nodeShell: &nodeShellRuntime{node: receipt.Node}, nativeOwners: []*Runtime{
		{Identity: &identity.Identity{Public: row.Owner, Private: old}, historicalOwner: true, reports: originalDB},
		{Identity: &identity.Identity{Public: [32]byte(middle.Public().(ed25519.PublicKey)), Private: middle}, historicalOwner: true, reports: middleDB},
	}}
	for _, owner := range runtime.nativeOwners {
		owner.parentRuntime, owner.controlIdentity = runtime, runtime.Identity
	}
	got, db, exists, err := runtime.nodeShellReceipt(row)
	if err != nil || !exists || db != originalDB || got.Owner != row.Owner || got.Origin != receipt.Origin || got.Instance != receipt.Instance || got.Pending.RequestID != receipt.Pending.RequestID || !bytes.Equal(got.Pending.Signature, receipt.Pending.Signature) {
		t.Fatal("two retained namespaces changed original effect/report", err)
	}
	seed, needed, err := nodeShellNextObservation(got, view, runtime.Identity.Public, 13)
	if err != nil || !needed || seed.Kind != "closed" {
		t.Fatal("positive original terminal receipt cannot settle", err)
	}
	signed := runtime.signNodeShellReport(view, seed)
	if signed.Reporter != runtime.Identity.Public || !ed25519.Verify(next.Public().(ed25519.PublicKey), control.NodeShellReportBytes(signed), signed.Signature) || ed25519.Verify(old.Public().(ed25519.PublicKey), control.NodeShellReportBytes(signed), signed.Signature) {
		t.Fatal("historical resource key became current report signer")
	}
	got.Pending = &signed
	if err := saveNodeShellObservationReplacement(db, receipt, got, nil); err != nil {
		t.Fatal(err)
	}
	stored, selected, exists, err := runtime.nodeShellReceipt(row)
	if err != nil || !exists || selected != originalDB || stored.Owner != receipt.Owner || stored.Origin != receipt.Origin || stored.Instance != receipt.Instance || stored.Pending.Reporter != runtime.Identity.Public {
		t.Fatal("current observation migrated original receipt namespace", err)
	}
	for _, other := range []*storage.DB{middleDB, currentDB} {
		if _, err := other.GetBounded(nodeShellReceiptKey(row.Session.SessionID), 8192); !errors.Is(err, storage.ErrMissing) {
			t.Fatal("recovery allocated another session receipt", err)
		}
	}
	foreign := row
	foreign.Owner = runtime.Identity.Public
	if _, _, _, err := runtime.nodeShellReceipt(foreign); err == nil {
		t.Fatal("current key adopted an original session owner")
	}
}

type nodeShellClosingNative struct {
	nodeShellStreamFake
	closeOnce sync.Once
	closed    chan struct{}
	waiting   chan struct{}
	release   chan struct{}
}

func (s *nodeShellClosingNative) Close() error {
	s.closeOnce.Do(func() { close(s.closed) })
	return nil
}
func (s *nodeShellClosingNative) Wait() (nodeshell.Exit, error) {
	<-s.closed
	close(s.waiting)
	<-s.release
	return nodeshell.Exit{Code: 7}, nil
}

func TestNodeShellRuntimeCloseWaitsBeforeOriginalReceiptStoreRelease(t *testing.T) {
	row, receipt := nodeShellReceiptFixture()
	receipt.Phase, receipt.OpenedAt, receipt.LastActivity = "opened", 11, 11
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Runtime.Close cancels producers before joining their native Wait.
	db, err := storage.Open(filepath.Join(t.TempDir(), "observations.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := saveNodeShellReceipt(db, receipt); err != nil {
		t.Fatal(err)
	}
	native := &nodeShellClosingNative{closed: make(chan struct{}), waiting: make(chan struct{}), release: make(chan struct{})}
	var release sync.Once
	defer release.Do(func() { close(native.release) })
	r := &Runtime{ctx: ctx, controlPolicy: control.Policy{Cluster: receipt.Cluster}, reports: db, nodeShell: &nodeShellRuntime{live: map[string]*NodeShellStream{}}}
	stream := &NodeShellStream{runtime: r, native: native, row: row.Session, receipt: receipt, db: db, done: make(chan struct{})}
	r.nodeShell.live[receipt.SessionID] = stream
	r.nodeShell.wg.Add(1)
	go func() { defer r.nodeShell.wg.Done(); stream.finish() }()
	joined := make(chan struct{})
	go func() { r.closeNodeShells(); close(joined) }()
	defer func() {
		_ = native.Close()
		release.Do(func() { close(native.release) })
		<-joined
	}()
	select {
	case <-native.waiting:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not close and Wait for original SSH")
	}
	select {
	case <-joined:
		t.Fatal("shutdown joined before native Wait finished")
	default:
	}
	release.Do(func() { close(native.release) })
	select {
	case <-joined:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not join original SSH finish")
	}
	end, err := stream.Wait()
	if !errors.Is(err, context.Canceled) || end.Code != 7 || end.Reason != "exit" || end.ClosedBy != nil {
		t.Fatal("shutdown fabricated actor or successful report", end, err)
	}
	raw, err := db.GetBounded(nodeShellReceiptKey(receipt.SessionID), 8192)
	stored, decodeErr := schema.Decode[nodeShellReceipt](raw)
	if err != nil || decodeErr != nil || stored.Phase != "closed" || stored.Code != 7 || stored.Owner != receipt.Owner || stored.Instance != receipt.Instance || stored.Origin != receipt.Origin {
		t.Fatal("shutdown released original store before durable terminal receipt", err, decodeErr)
	}
	if !r.nodeShell.closed || len(r.nodeShell.live) != 0 {
		t.Fatal("shutdown retained an open native handle")
	}
}
