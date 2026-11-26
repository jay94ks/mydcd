// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/storage"
)

// The frozen original state is input to product reducers only. The outer
// report admission is injected for this candidate-validation check; no member
// signature, live quorum, DB write or native success is claimed here.
func TestClosedOriginalManualCDContinuationCheckpoint(t *testing.T) {
	prefix := os.Getenv("MYDC_E8_CLOSED_SOURCE_PREFIX")
	if prefix == "" {
		t.Skip("explicit stopped E8 state")
	}
	root, err := filepath.Abs("../../..")
	if err != nil || prefix != filepath.Join(root, "work/e8-kvm-current1/inputs/current189-closed-node-a-") {
		t.Fatal("unplanned closed input", err)
	}
	read := func(name, key string, limit int) []byte {
		path := prefix + name
		raw, err := os.ReadFile(path)
		var meta struct {
			Size   int64
			SHA256 string
		}
		metadata, metaErr := os.ReadFile(path + ".json")
		sum := sha256.Sum256(raw)
		if err != nil || metaErr != nil || json.Unmarshal(metadata, &meta) != nil || meta.Size != int64(len(raw)) || meta.SHA256 != hex.EncodeToString(sum[:]) {
			t.Fatal("closed input binding")
		}
		t.Cleanup(func() {
			after, e := os.ReadFile(path)
			if e != nil || sha256.Sum256(after) != sum {
				t.Error("original input changed", e)
			}
		})
		db, err := storage.OpenReadOnly(path)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		value, err := db.GetBounded(key, limit)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	// The KVM source review already verified this installation's signature.
	// Keep the dependency direction: bootstrap itself imports this package.
	var installed struct {
		Root struct {
			Cluster, TrustRoot [32]byte
			Self               struct{ Key [32]byte }
		}
		Admin   [32]byte
		Genesis config.Peer
	}
	if json.Unmarshal(read("installation.db", "installation", 1<<20), &installed) != nil || installed.Root.Cluster == ([32]byte{}) || installed.Root.TrustRoot == ([32]byte{}) || installed.Genesis.Key != hex.EncodeToString(installed.Root.TrustRoot[:]) {
		t.Fatal("closed installation")
	}
	var record struct{ State []byte }
	if json.Unmarshal(read("control-fsm.db", "fsm", 64<<20), &record) != nil {
		t.Fatal("closed FSM")
	}
	s, err := state.Decode(record.State)
	if err != nil {
		t.Fatal(err)
	}
	p := Policy{Cluster: installed.Root.Cluster, TrustRoot: installed.Root.TrustRoot, BootstrapKey: installed.Admin, Genesis: installed.Genesis}
	p, err = p.Current(s)
	if err != nil {
		t.Fatal(err)
	}
	members, err := p.Members(s)
	if err != nil {
		t.Fatal(err)
	}
	at := uint64(time.Now().Unix())
	for _, member := range members.Entries {
		key, e := hex.DecodeString(member.Peer.Key)
		if e != nil || len(key) != 32 {
			t.Fatal("member key")
		}
		var caller [32]byte
		copy(caller[:], key)
		work, err := p.AppDeliverySyncWork(s, caller, AppDeliveryWorkRequest{Tenant: "tenant", App: "app", At: at, TargetCAS: true})
		t.Logf("original member=%s work=%t controller_action=%s reason=%s error=%v", member.Peer.ID, members.WorkKey(caller), work.Action, work.Reason, err)
	}
	a, err := p.Apps(s)
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := a.entries[appKey("tenant", "app")]
	if !ok {
		t.Fatal("original app absent")
	}
	entry, err = p.continueCDSync(s, entry, at)
	if err != nil {
		t.Fatal("original deterministic continue", err)
	}
	a.entries[appKey("tenant", "app")] = entry
	writes, code := p.appsCheckpoint(s, a)
	if code != state.Applied {
		t.Fatal("original checkpoint encode", code)
	}
	cmd := state.Command{Kind: state.ModuleReport, Actor: "node/" + hex.EncodeToString(installed.Root.Self.Key[:]), Epoch: s.ModuleEpoch(), Key: AppsKey, Expected: s.Object(AppsKey).Revision, Value: "injected outer report; real checkpoint candidate"}
	cmd.RequestID = state.ReportRequestID(cmd)
	validate := func(before, after state.State, command state.Command) error {
		_, appErr := p.Apps(after)
		t.Logf("continued checkpoint decode=%v", appErr)
		return p.ValidateManaged(before, after, command)
	}
	_, result, err := state.ApplyTransactional(s, s.Index()+1, cmd, validate, func(state.State, state.Command) (map[string][]byte, state.Code) { return writes, state.Applied }, func(state.State, state.Command) bool { return true }, nil, nil)
	if err != nil || result.Code != state.Applied {
		t.Fatal("original complete continuation checkpoint rejected", result, err)
	}
}

func deliverySyncProofFixture(t *testing.T, automatic bool) (*backupCoreFixture, appEntry, AppDeliverySync) {
	t.Helper()
	f := deliveryControlFixture(t)
	a, err := f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	entry := a.entries[appKey("tenant", "source-app")]
	choice := AppDeliveryChoice{Operation: "next-sync", Candidate: [32]byte{1}, Registration: appRegistrationDigest(entry.Origin)}
	proof := AppDeliverySync{Choice: choice, Plan: [32]byte{2}, Intent: [32]byte{3}, Artifact: [32]byte{4}, Epoch: f.s.ModuleEpoch()}
	if automatic {
		r := AppDeliveryProgress{Schema: 1, Kind: "app-delivery", Cluster: f.p.Cluster, Reporter: [32]byte(f.node.Public().(ed25519.PublicKey)), Tenant: "tenant", App: "source-app", Action: "auto-sync", Expected: entry.Delivery.Revision(), RootRevision: f.s.Object(AppsKey).Revision, Epoch: proof.Epoch, At: 10, Choice: &choice}
		r.Signature = ed25519.Sign(f.node, AppDeliveryProgressBytes(r))
		proof.Member = &r
	} else {
		payload, _ := json.Marshal(AppCDChange{Tenant: "tenant", App: "source-app", Choice: &choice})
		u := UserOperation{Schema: 1, Session: f.session, At: 10, Epoch: proof.Epoch, RequestID: "sync-request", RootRevision: f.s.Object(AppsKey).Revision, Change: Change{Schema: 1, Principal: "admin", Action: "sync-app", Expected: entry.Delivery.Revision(), Payload: payload}}
		u.Signature = ed25519.Sign(f.admin, OperationBytes(u))
		proof.User = &u
	}
	return f, entry, proof
}

func TestDeliverySyncOriginKeepsRegistrationAndOriginalSubmitter(t *testing.T) {
	for _, automatic := range []bool{false, true} {
		f, entry, proof := deliverySyncProofFixture(t, automatic)
		original, _ := json.Marshal(entry.Origin)
		initial, err := appExecutionOrigin(entry.Origin, nil, entry.Inventory.Scope())
		if err != nil {
			t.Fatal(err)
		}
		selected, err := appExecutionOrigin(entry.Origin, &proof, entry.Inventory.Scope())
		if err != nil || selected.Operation != proof.Choice.Operation || selected.Submitter != initial.Submitter || selected.Epoch != proof.Epoch {
			t.Fatal("original source delegation was replaced", selected, err)
		}
		current := entry
		current.Sync = &proof
		if current.downTarget() == entry.downTarget() {
			t.Fatal("old app down could select a subsequent sync")
		}
		after, _ := json.Marshal(entry.Origin)
		if !bytes.Equal(original, after) {
			t.Fatal("sync rewrote signed registration")
		}
		if automatic {
			// A historical member signature is retained after membership changes;
			// admission of a NEW report still requires a current member.
			old := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{66}, 32))
			proof.Member.Reporter = [32]byte(old.Public().(ed25519.PublicKey))
			proof.Member.Signature = ed25519.Sign(old, AppDeliveryProgressBytes(*proof.Member))
			if proof.verify(entry.Origin, entry.Inventory.Scope()) != nil {
				t.Fatal("historical source proof required current membership")
			}
			command, err := proof.Member.Command()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.p.appDeliveryProgress(f.s, command); err == nil {
				t.Fatal("historical signer gained new authority")
			}
		}
	}
}

func TestDeliverySyncProofRejectsChangedChoiceScopeAndMalformedMember(t *testing.T) {
	_, entry, manual := deliverySyncProofFixture(t, false)
	_, _, automatic := deliverySyncProofFixture(t, true)
	clone := func(p AppDeliverySync) AppDeliverySync {
		raw, _ := json.Marshal(p)
		var n AppDeliverySync
		if json.Unmarshal(raw, &n) != nil {
			t.Fatal("clone")
		}
		return n
	}
	for name, mutate := range map[string]func(*AppDeliverySync){
		"operation":        func(p *AppDeliverySync) { p.Choice.Operation = "another" },
		"registration":     func(p *AppDeliverySync) { p.Choice.Registration[0] ^= 1 },
		"candidate":        func(p *AppDeliverySync) { p.Choice.Candidate[0] ^= 1 },
		"epoch":            func(p *AppDeliverySync) { p.Epoch++ },
		"missing-intent":   func(p *AppDeliverySync) { p.Intent = [32]byte{} },
		"missing-artifact": func(p *AppDeliverySync) { p.Artifact = [32]byte{} },
		"two-authorities":  func(p *AppDeliverySync) { p.Member = automatic.Member },
	} {
		t.Run(name, func(t *testing.T) {
			p := clone(manual)
			mutate(&p)
			if p.verify(entry.Origin, entry.Inventory.Scope()) == nil {
				t.Fatal("changed original proof accepted")
			}
		})
	}
	f, _, _ := deliverySyncProofFixture(t, true)
	for name, mutate := range map[string]func(*AppDeliveryProgress){
		"zero-cas":         func(p *AppDeliveryProgress) { p.Expected = 0 },
		"zero-root":        func(p *AppDeliveryProgress) { p.RootRevision = 0 },
		"overflow-time":    func(p *AppDeliveryProgress) { p.At = math.MaxUint64 },
		"foreign-tenant":   func(p *AppDeliveryProgress) { p.Tenant = "another" },
		"source-ticket":    func(p *AppDeliveryProgress) { p.Ticket = &deployment.DeliveryFetch{} },
		"different-action": func(p *AppDeliveryProgress) { p.Action = "fetch" },
	} {
		t.Run(name, func(t *testing.T) {
			p := clone(automatic)
			mutate(p.Member)
			p.Member.Signature = ed25519.Sign(f.node, AppDeliveryProgressBytes(*p.Member))
			if p.verify(entry.Origin, entry.Inventory.Scope()) == nil {
				t.Fatal("malformed signed sync proof accepted")
			}
		})
	}
}

func TestDeliveryManualPauseResumeCASAndCandidateBoundSync(t *testing.T) {
	f := deliveryControlFixture(t)
	a, _ := f.p.Apps(f.s)
	entry := a.entries[appKey("tenant", "source-app")]
	choice, _ := entry.Delivery.CandidateSelection()
	q := AppCDChange{Tenant: "tenant", App: "source-app"}
	initial, _ := entry.Inventory.Encode()
	f.apply("pause-source", "pause-app-cd", entry.Delivery.Revision(), q, state.Applied)
	a, err := f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	entry = a.entries[appKey("tenant", "source-app")]
	if !entry.Delivery.Paused() {
		t.Fatal("CD pause was not stored")
	}
	work, err := f.p.AppDeliverySyncWork(f.s, [32]byte(f.node.Public().(ed25519.PublicKey)), AppDeliveryWorkRequest{Tenant: "tenant", App: "source-app", At: 10})
	if err != nil || work.Action != "" {
		t.Fatal("paused source scheduled automatic work", work, err)
	}
	f.apply("stale-resume-source", "resume-app-cd", entry.Delivery.Revision()-1, q, state.ConditionFailed)
	f.apply("resume-source", "resume-app-cd", entry.Delivery.Revision(), q, state.Applied)
	a, err = f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	entry = a.entries[appKey("tenant", "source-app")]
	if entry.Delivery.Paused() || entry.Inventory.Scope().App != "source-app" {
		t.Fatal("resume lost source registration")
	}
	if current, _ := entry.Delivery.CandidateSelection(); current != choice {
		t.Fatal("pause/resume replaced frozen source candidate")
	}
	q.Choice = &AppDeliveryChoice{Operation: "replacement", Candidate: [32]byte{77}, Registration: appRegistrationDigest(entry.Origin)}
	f.apply("different-candidate", "sync-app", entry.Delivery.Revision(), q, state.ConditionFailed)
	a, _ = f.p.Apps(f.s)
	entry = a.entries[appKey("tenant", "source-app")]
	active, _ := entry.Inventory.Active()
	if active.ID != "run-source-app" || entry.Sync != nil {
		t.Fatal("rejected candidate replaced the original execution")
	}
	after, _ := entry.Inventory.Encode()
	if bytes.Equal(initial, after) {
		t.Fatal("fixture did not exercise execution pause/resume")
	}
}
