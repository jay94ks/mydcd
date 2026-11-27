// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"sync"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
)

func permitDecodeFixture(t *testing.T) (*backupCoreFixture, [32]byte, AppBindingRequest) {
	t.Helper()
	f := managedDNSTaskCoreFixture(t)
	task := managedDNSTaskCoreBegin(t, f, "first", "10.80.1.10", "first")
	managedDNSTaskCoreSubmit(t, f, "first", deployment.ResourceKey("network-ref", "tenant", "first", "lan/node-a"), true, state.Applied)
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	managedDNSTaskCoreSubmit(t, f, "first", task, true, state.Applied)
	managedDNSTaskCoreProgress(t, f, "first", "bind-inputs", task, nil)
	a, err := f.p.Apps(f.s)
	o := f.s.Object(task)
	ref := deployment.ObjectRef{Key: task, Generation: o.Generation, Revision: o.Revision}
	b, ok := a.Binding(ref)
	if err != nil || !ok {
		t.Fatal("binding fixture", err)
	}
	return f, [32]byte(f.node.Public().(ed25519.PublicKey)), AppBindingRequest{Task: ref, Digest: b.Digest(), At: 10}
}

// Explicit invalid/counterfactual FSM input, never a product mutation adapter.
func permitDecodeWrites(t *testing.T, s state.State, key string, writes map[string][]byte) state.State {
	t.Helper()
	cmd := state.Command{Kind: state.Module, Actor: "anchor", Epoch: 1, RequestID: "decode-counterexample", Key: key, Expected: s.Object(key).Revision, Value: "fixture"}
	next, result, err := state.ApplyReduced(s, s.Index()+1, cmd, nil, func(state.State, state.Command) (map[string][]byte, state.Code) { return writes, state.Applied })
	if err != nil || result.Code != state.Applied {
		t.Fatal(result, err)
	}
	return next
}

func TestPermitAppsDecodeRetainsCurrentChecksAndOwnedViews(t *testing.T) {
	f, owner, q := permitDecodeFixture(t)
	permitAppsDecoded.Store(nil)
	first, err := f.p.AppBindingPermit(f.s, owner, q)
	if err != nil {
		t.Fatal(err)
	}
	cached := permitAppsDecoded.Load()
	if cached == nil {
		t.Fatal("decode not retained")
	}
	second, err := f.p.AppBindingPermit(f.s, owner, q)
	if err != nil || permitAppsDecoded.Load() != cached || !bytes.Equal(first.Binding, second.Binding) || first.ReadSet != second.ReadSet {
		t.Fatal("unchanged decode/permit", err)
	}
	first.Binding[0] ^= 1
	third, err := f.p.AppBindingPermit(f.s, owner, q)
	if err != nil || !bytes.Equal(second.Binding, third.Binding) {
		t.Fatal("returned bytes poisoned decode", err)
	}
	owned, err := f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	delete(owned.entries, appKey("tenant", "first"))
	if _, err = f.p.AppBindingPermit(f.s, owner, q); err != nil {
		t.Fatal("reducer view aliased decode", err)
	}
	// A Task-only change leaves the Apps bytes exactly the same.
	task := f.s.Object(q.Task.Key)
	changed, result, err := state.Apply(f.s, f.s.Index()+1, state.Command{Actor: "anchor", Epoch: 1, RequestID: "task-counterexample", Key: q.Task.Key, Expected: task.Revision, Value: task.Value + " "})
	if err != nil || result.Code != state.Applied {
		t.Fatal(result, err)
	}
	if _, err = f.p.AppBindingPermit(changed, owner, q); err == nil {
		t.Fatal("old Task grant cached")
	}
	foreign := owner
	foreign[0] ^= 1
	if _, err = f.p.AppBindingPermit(f.s, foreign, q); err == nil {
		t.Fatal("old member grant cached")
	}
	bad := q
	bad.Digest[0] ^= 1
	if _, err = f.p.AppBindingPermit(f.s, owner, bad); err == nil {
		t.Fatal("old binding grant cached")
	}
	bad = q
	bad.At = -1
	if _, err = f.p.AppBindingPermit(f.s, owner, bad); err == nil {
		t.Fatal("invalid time cached")
	}
	// A current catalog credential change must still deny, without Apps mutation.
	c, _ := f.p.Catalog(f.s)
	u, _ := c.User("admin")
	expected := u.Revision
	u.Revision = 0
	u.Username = "renamed-admin"
	c, err = c.PutUser("admin", expected, accountFields(u))
	if err != nil {
		t.Fatal(err)
	}
	rawCatalog, _ := c.Encode()
	writes, code := writeCheckpoint(f.s, CatalogKey, f.p.Cluster, f.p.BootstrapKey, c.Revision(), rawCatalog)
	if code != state.Applied {
		t.Fatal(code)
	}
	changed = permitDecodeWrites(t, f.s, CatalogKey, writes)
	if _, err = f.p.AppBindingPermit(changed, owner, q); err == nil {
		t.Fatal("current revoked user bypassed")
	}
	if permitAppsDecoded.Load() != cached {
		t.Fatal("current change should not replace Apps parse")
	}
}

func TestPermitAppsDecodeVerifiesActualCheckpointAndPolicy(t *testing.T) {
	f, owner, q := permitDecodeFixture(t)
	permitAppsDecoded.Store(nil)
	if _, err := f.p.AppBindingPermit(f.s, owner, q); err != nil {
		t.Fatal(err)
	}
	cached := permitAppsDecoded.Load()
	key := storedPart(t, f.s, AppsKey)
	part := f.s.Object(key)
	damaged := permitDecodeWrites(t, f.s, key, map[string][]byte{key: []byte(part.Value + " ")})
	if _, err := f.p.AppBindingPermit(damaged, owner, q); err == nil {
		t.Fatal("parts/digest bypassed")
	}
	// Same logical revision, different actual content with a valid outer digest.
	var disk appCheckpoint
	if err := json.Unmarshal(cached.raw, &disk); err != nil {
		t.Fatal(err)
	}
	disk.Schema = 2
	raw, _ := json.Marshal(disk)
	writes, code := writeCheckpoint(f.s, AppsKey, f.p.Cluster, f.p.TrustRoot, cached.revision, raw)
	if code != state.Applied {
		t.Fatal(code)
	}
	changed := permitDecodeWrites(t, f.s, AppsKey, writes)
	if _, err := f.p.AppBindingPermit(changed, owner, q); err == nil {
		t.Fatal("same revision replaced bytes reused")
	}
	if permitAppsDecoded.Load() != cached {
		t.Fatal("invalid parse cached")
	}
	for _, field := range []string{"cluster", "trust", "bootstrap"} {
		p := f.p
		switch field {
		case "cluster":
			p.Cluster[0] ^= 1
		case "trust":
			p.TrustRoot[0] ^= 1
		case "bootstrap":
			p.BootstrapKey[0] ^= 1
		}
		if _, err := p.AppBindingPermit(f.s, owner, q); err == nil {
			t.Fatal("foreign policy reused", field)
		}
	}
	// Existence is part of decode validation, independently of permission checks.
	empty, _ := access.New(f.p.BootstrapKey)
	user, _ := func() (access.User, bool) { c, _ := f.p.Catalog(f.s); return c.User("admin") }()
	user.Revision = 0
	empty, err := empty.Enroll(f.p.BootstrapKey, user)
	if err != nil {
		t.Fatal(err)
	}
	rawCatalog, _ := empty.Encode()
	writes, code = writeCheckpoint(f.s, CatalogKey, f.p.Cluster, f.p.BootstrapKey, empty.Revision(), rawCatalog)
	if code != state.Applied {
		t.Fatal(code)
	}
	changed = permitDecodeWrites(t, f.s, CatalogKey, writes)
	if _, err := f.p.readOnlyApps(changed); err == nil {
		t.Fatal("missing current tenant/user ignored")
	}
}

func TestPermitAppsDecodeConcurrentReads(t *testing.T) {
	f, owner, q := permitDecodeFixture(t)
	permitAppsDecoded.Store(nil)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() { _, err := f.p.AppBindingPermit(f.s, owner, q); errs <- err })
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}
