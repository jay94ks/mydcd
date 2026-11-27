// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
)

// Compare the product-owned view to the original full decoder, including the
// exact next checkpoint writes. The reference is not a second reducer.
func requireOwnedAppSnapshot(t *testing.T, f *backupCoreFixture) (Apps, []byte) {
	t.Helper()
	raw, revision, err := readCheckpoint(f.s, AppsKey, f.p.Cluster, f.p.TrustRoot)
	if err != nil {
		t.Fatal(err)
	}
	full, err := f.p.decodeApps(f.s, raw, revision)
	if err != nil {
		t.Fatal(err)
	}
	want, code := f.p.appsCheckpoint(f.s, full)
	if code != state.Applied {
		t.Fatal(code)
	}
	owned, err := f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	got, code := f.p.appsCheckpoint(f.s, owned)
	wantBytes, _ := json.Marshal(want)
	gotBytes, _ := json.Marshal(got)
	if code != state.Applied || !bytes.Equal(wantBytes, gotBytes) {
		t.Fatal("owned copy differs from original decoder checkpoint", code)
	}
	return owned, wantBytes
}

func TestOwnedAppsCopyIsolatesBindingsOriginsAndNetwork(t *testing.T) {
	f, _, _ := permitDecodeFixture(t)
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	permitAppsDecoded.Store(nil)
	owned, want := requireOwnedAppSnapshot(t, f)
	cached := permitAppsDecoded.Load()
	if cached == nil || owned.network == nil || len(owned.sources) == 0 || len(owned.network.Groups) == 0 {
		t.Fatal("rich network fixture")
	}
	key := appKey("tenant", "first")
	entry := owned.entries[key]
	entry.Origin.Signature[0] ^= 1
	entry.Origin.Change.Payload[0] ^= 1
	entry.Origin.Session.Scopes[0].Actions[0] = "caller-mutation"
	owned.sources[0].Origin.Signature[0] ^= 1
	owned.network.Groups[0].Owners[0].Config.Zone = "caller.invalid"
	if owned.network.Groups[0].Owners[0].Managed != nil {
		owned.network.Groups[0].Owners[0].Managed.Node = "caller-mutated"
	}
	delete(owned.entries, key)
	// Neither a reducer's map nor its nested control fields may publish a new
	// fact to the borrowed view. State bytes and current validation are unchanged.
	_, again := requireOwnedAppSnapshot(t, f)
	if !bytes.Equal(want, again) || permitAppsDecoded.Load() != cached {
		t.Fatal("owned metadata mutation contaminated borrowed view")
	}
}

func TestOwnedAppsCopyIsolatesDeliveryAndPartialUpload(t *testing.T) {
	f := deliveryControlFixture(t)
	deliveryControlProgress(t, f, AppDeliveryProgress{Action: "fetch"}, state.Applied)
	a, _ := f.p.Apps(f.s)
	d, _ := a.Delivery("tenant", "source-app")
	ticket, _ := d.FetchTicket()
	body := bytes.Repeat([]byte("x"), deployment.ArtifactPartBytes+1)
	input := AppDeliveryInput{Ticket: ticket, Upload: "owned-copy-input", Commit: strings.Repeat("1", 40)}
	begin := AppUploadBegin{Tenant: "tenant", App: "source-app", Deployment: "deploy", ID: input.Upload, Length: len(body), Digest: sha256.Sum256(body)}
	deliveryControlProgress(t, f, AppDeliveryProgress{Action: "input", Ticket: &ticket, Input: &input, Begin: &begin}, state.Applied)
	deliveryControlProgress(t, f, AppDeliveryProgress{Action: "part", Ticket: &ticket, Part: &AppUploadPart{Tenant: "tenant", ID: input.Upload, Index: 0, Data: body[:deployment.ArtifactPartBytes]}}, state.Applied)
	permitAppsDecoded.Store(nil)
	owned, want := requireOwnedAppSnapshot(t, f)
	cached := permitAppsDecoded.Load()
	entry := owned.entries[appKey("tenant", "source-app")]
	if entry.Delivery == nil || entry.DeliveryInput == nil || len(owned.uploads) != 1 || len(owned.uploads[0].Parts[0]) == 0 {
		t.Fatal("partial delivery fixture")
	}
	entry.DeliveryInput.Commit = "caller-mutated"
	*entry.Delivery = deployment.Delivery{}
	entry.Origin.Signature[0] ^= 1
	owned.uploads[0].Parts[0][0] ^= 1
	_, again := requireOwnedAppSnapshot(t, f)
	if !bytes.Equal(want, again) || permitAppsDecoded.Load() != cached {
		t.Fatal("owned delivery/part mutation contaminated borrowed view")
	}
	// Exercise every optional control pointer, independent of a particular
	// accepted FSM phase. This adversarial copy input is never installed.
	original, err := f.p.ReadApps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	base := original.entries[appKey("tenant", "source-app")]
	down := base.Origin
	base.Down = &down
	base.Compacted = &deployment.OperationSummary{ID: "original", Status: "closed"}
	base.Sync = &AppDeliverySync{User: &down}
	base.PendingSync = &AppDeliverySync{User: &down}
	synthetic := Apps{entries: map[string]appEntry{"entry": base}}
	wantSignature := bytes.Clone(down.Signature)
	wantPayload := bytes.Clone(down.Change.Payload)
	copied, err := synthetic.owned()
	if err != nil {
		t.Fatal(err)
	}
	clone := copied.entries["entry"]
	clone.Down.Signature[0] ^= 1
	clone.Compacted.ID = "caller-mutated"
	clone.Sync.User.Signature[0] ^= 1
	clone.PendingSync.User.Change.Payload[0] ^= 1
	if base.Compacted.ID != "original" || !bytes.Equal(base.Down.Signature, wantSignature) || !bytes.Equal(base.Sync.User.Signature, wantSignature) || !bytes.Equal(base.PendingSync.User.Change.Payload, wantPayload) {
		t.Fatal("optional metadata pointer aliases its source")
	}
}
