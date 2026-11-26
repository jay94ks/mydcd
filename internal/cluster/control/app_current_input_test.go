// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/storage"
)

// Test-only corruption of existing rows in an owned canonical snapshot. This
// is not a management/native adapter and never writes the original FSM/DB.
func structuralSnapshotWrites(t *testing.T, s state.State, writes map[string][]byte) state.State {
	t.Helper()
	raw, err := state.Encode(s)
	if err != nil {
		t.Fatal(err)
	}
	var disk struct {
		Schema  uint8
		Index   uint64
		Objects []struct {
			Key                  string
			Revision, Generation uint64
			Value                []byte
			Present              bool
		}
		Principals   json.RawMessage
		Receipts     json.RawMessage
		Window       json.RawMessage `json:",omitempty"`
		Reports      json.RawMessage `json:",omitempty"`
		ReportFloors json.RawMessage `json:",omitempty"`
	}
	if json.Unmarshal(raw, &disk) != nil {
		t.Fatal("snapshot fixture")
	}
	changed := 0
	for i := range disk.Objects {
		if value, ok := writes[disk.Objects[i].Key]; ok {
			disk.Objects[i].Value = value
			disk.Objects[i].Present = value != nil
			changed++
		}
	}
	if changed != len(writes) {
		t.Fatal("counterexample must alter existing objects only")
	}
	raw, err = json.Marshal(disk)
	if err != nil {
		t.Fatal(err)
	}
	next, err := state.Decode(raw)
	if err != nil || next.Index() != s.Index() {
		t.Fatal("same-index snapshot counterexample", err)
	}
	return next
}

func TestPermitAppsStructuralReuseComparesWholeCurrentInput(t *testing.T) {
	f, _, q := permitDecodeFixture(t)
	permitAppsDecoded.Store(nil)
	if _, err := f.p.ReadApps(f.s); err != nil {
		t.Fatal(err)
	}
	decoded := permitAppsDecoded.Load()
	original := decoded.current.Load()
	if _, err := f.p.ReadApps(f.s); err != nil || decoded.current.Load() != original {
		t.Fatal("identical structural input was not reused", err)
	}
	// Equal ordinals are not identities: both forks start at the same state.
	key := q.Task.Key
	originalValue := f.s.Object(key).Value
	a := structuralSnapshotWrites(t, f.s, map[string][]byte{key: []byte(originalValue + " ")})
	b := structuralSnapshotWrites(t, f.s, map[string][]byte{key: []byte(originalValue + "  ")})
	if a.Index() != b.Index() {
		t.Fatal("counterexample requires the same ordinal")
	}
	if _, err := f.p.ReadApps(a); err != nil {
		t.Fatal(err)
	}
	first := decoded.current.Load()
	if _, err := f.p.ReadApps(b); err != nil || decoded.current.Load() == first || decoded.current.Load().objects[key].Value != originalValue+"  " {
		t.Fatal("same-index different bytes reused structural success", err)
	}
	good := decoded.current.Load()
	part := partKey(CatalogKey, 0)
	bad := structuralSnapshotWrites(t, b, map[string][]byte{part: []byte(b.Object(part).Value + " ")})
	if _, err := f.p.ReadApps(bad); err == nil || decoded.current.Load() != good {
		t.Fatal("changed Catalog bypassed validation or poisoned last success")
	}
	if _, err := f.p.ReadApps(b); err != nil || decoded.current.Load() != good {
		t.Fatal("original exact input did not recover", err)
	}
	p := f.p
	p.Genesis.Endpoint += "-different"
	if _, err := p.ReadApps(b); err != nil || decoded.current.Load() == good {
		t.Fatal("Genesis was not part of the structural input", err)
	}
}

// Reuse the exact closed E8 input; no DB mutation, credentials, clocks in the
// product transition, native effect or substituted implementation is involved.
func TestClosedTargetAppsStructuralReuseRejectsChangedVolume(t *testing.T) {
	prefix := os.Getenv("MYDC_E8_TARGET_CLOSED_SOURCE_PREFIX")
	if prefix == "" {
		t.Skip("explicit original closed target input required")
	}
	root, err := filepath.Abs("../../..")
	if err != nil || prefix != filepath.Join(root, "work/e8-kvm-current1/inputs/current233-closed-node-a-") {
		t.Fatal("unplanned closed target input", err)
	}
	read := func(name, key string) []byte {
		t.Helper()
		path := prefix + name
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var meta struct {
			Size   int64
			SHA256 string
		}
		metadata, err := os.ReadFile(path + ".json")
		sum := sha256.Sum256(raw)
		if err != nil || json.Unmarshal(metadata, &meta) != nil || meta.Size != int64(len(raw)) || meta.SHA256 != hex.EncodeToString(sum[:]) {
			t.Fatal("closed source binding")
		}
		t.Cleanup(func() {
			after, err := os.ReadFile(path)
			if err != nil || sha256.Sum256(after) != sum {
				t.Error("original closed input changed", err)
			}
		})
		db, err := storage.OpenReadOnly(path)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		value, err := db.GetBounded(key, 64<<20)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	var installed struct {
		Root    struct{ Cluster, TrustRoot [32]byte }
		Admin   [32]byte
		Genesis config.Peer
	}
	if json.Unmarshal(read("installation.db", "installation"), &installed) != nil {
		t.Fatal("installation binding")
	}
	var record struct{ State []byte }
	if json.Unmarshal(read("control-fsm.db", "fsm"), &record) != nil {
		t.Fatal("closed FSM")
	}
	s, err := state.Decode(record.State)
	if err != nil {
		t.Fatal(err)
	}
	p := Policy{Cluster: installed.Root.Cluster, TrustRoot: installed.Root.TrustRoot, BootstrapKey: installed.Admin, Genesis: installed.Genesis}
	permitAppsDecoded.Store(nil)
	apps, err := p.ReadApps(s)
	if err != nil {
		t.Fatal("original target Apps", err)
	}
	entry := apps.entries[appKey("tenant", "app")]
	active, ok := entry.Inventory.Active()
	if !ok || active.ID != "e8-cold-move-after-replay" {
		t.Fatal("original target operation changed")
	}
	decoded := permitAppsDecoded.Load()
	current := decoded.current.Load()
	began := time.Now()
	for range 3 {
		if err := p.validatePermitAppsCurrent(s, apps); err != nil {
			t.Fatal(err)
		}
	}
	full := time.Since(began)
	began = time.Now()
	for range 3 {
		if _, err := p.ReadApps(s); err != nil || decoded.current.Load() != current {
			t.Fatal("exact source reuse", err)
		}
	}
	t.Logf("three original structural validations=%s; three whole-input checked ReadApps=%s; no native/Healthy claim", full, time.Since(began))
	raw, revision, err := readCheckpoint(s, VolumesKey, p.Cluster, p.TrustRoot)
	var disk volumeCheckpoint
	if err != nil || json.Unmarshal(raw, &disk) != nil || len(disk.Entries) == 0 {
		t.Fatal("original Volume checkpoint")
	}
	// Preserve logical revision and recompute the outer checkpoint digest:
	// the changed signed native fact itself must still be rejected.
	disk.Entries[0].Native.Signature[0] ^= 1
	changedRaw, _ := json.Marshal(disk)
	writes, code := writeCheckpoint(s, VolumesKey, p.Cluster, p.TrustRoot, revision, changedRaw)
	if code != state.Applied {
		t.Fatal(code)
	}
	changed := structuralSnapshotWrites(t, s, writes)
	if _, err := p.ReadApps(changed); err == nil || decoded.current.Load() != current {
		t.Fatal("changed Volume native proof reused old success")
	}
	part := partKey(VolumesKey, 0)
	corrupt := structuralSnapshotWrites(t, s, map[string][]byte{part: []byte(s.Object(part).Value + " ")})
	if _, err := p.ReadApps(corrupt); err == nil || decoded.current.Load() != current {
		t.Fatal("changed Volume checkpoint part reused old success")
	}
	if _, err := p.ReadApps(s); err != nil || decoded.current.Load() != current {
		t.Fatal("exact original target failed after invalid counterexamples", err)
	}
}
