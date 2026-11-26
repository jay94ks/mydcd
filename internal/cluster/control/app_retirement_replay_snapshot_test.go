// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/storage"
	"os"
	"path/filepath"
	"testing"
)

// Product reducers on the exact original closed E8 state. Outer command/report
// admission is injected; actual authentication/MYDCP/Raft are covered separately.
// Original files are opened read-only and checked unchanged after this test.
func TestClosedOriginalRetirementReplayReachesQuiescenceWithoutExtendingMove(t *testing.T) {
	prefix := os.Getenv("MYDC_E8_RETIREMENT_CLOSED_SOURCE_PREFIX")
	if prefix == "" {
		t.Skip("explicit original closed E8 input")
	}
	root, err := filepath.Abs("../../..")
	if err != nil || prefix != filepath.Join(root, "work/e8-kvm-current1/inputs/current230-closed-node-a-") {
		t.Fatal("unplanned original input", err)
	}
	read := func(name, key string) []byte {
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
			t.Fatal("original closed input binding")
		}
		t.Cleanup(func() {
			after, e := os.ReadFile(path)
			if e != nil || sha256.Sum256(after) != sum {
				t.Error("original input modified", e)
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
		Root struct {
			Cluster, TrustRoot [32]byte
			Self               struct{ Key [32]byte }
		}
		Admin   [32]byte
		Genesis config.Peer
	}
	if json.Unmarshal(read("installation.db", "installation"), &installed) != nil || installed.Genesis.Key != hex.EncodeToString(installed.Root.TrustRoot[:]) {
		t.Fatal("original installation binding")
	}
	var record struct{ State []byte }
	if json.Unmarshal(read("control-fsm.db", "fsm"), &record) != nil {
		t.Fatal("original FSM")
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
	registry, err := p.Volumes(s)
	if err != nil {
		t.Fatal(err)
	}
	var job VolumeMove
	for _, j := range registry.Moves() {
		if j.Binding.ID == "e8-cold-move-default-budget" {
			job = j
		}
	}
	if job.Binding.ID == "" {
		t.Fatal("original accepted move absent")
	}
	at := job.ExpiresAt + 1 // cleanup after the immutable move deadline
	checkpoint := func(writes map[string][]byte, code state.Code) {
		t.Helper()
		if code != state.Applied {
			t.Fatal("product reducer", code)
		}
		cmd := state.Command{Kind: state.ModuleReport, Actor: "node/" + hex.EncodeToString(installed.Root.Self.Key[:]), Epoch: s.ModuleEpoch(), Key: AppsKey, Expected: s.Object(AppsKey).Revision, Value: "injected outer admission; product checkpoint"}
		cmd.RequestID = state.ReportRequestID(cmd)
		next, result, err := state.ApplyTransactional(s, s.Index()+1, cmd, p.ValidateManaged, func(state.State, state.Command) (map[string][]byte, state.Code) { return writes, code }, func(state.State, state.Command) bool { return true }, nil, nil)
		if err != nil || result.Code != state.Applied {
			t.Fatal("product checkpoint", result, err)
		}
		s = next
	}
	apps, err := p.Apps(s)
	if err != nil {
		t.Fatal(err)
	}
	entry := apps.entries[appKey("tenant", "app")]
	retirement, found := entry.Inventory.Retirement()
	if !found {
		t.Fatal("original retirement absent")
	}
	key := "workload/cd/tenant/app/source"
	original, found := entry.Inventory.Removal(key, "delete")
	if !found {
		t.Fatal("original Delete absent")
	}
	q := AppRetirementReplay{Tenant: "tenant", App: "app", Retirement: retirement.ID, Key: key, Phase: "delete", Command: state.Digest(original.Command)}
	op := UserOperation{Schema: 1, Session: job.Origin.Session, At: at, RequestID: "closed-original-replay", Change: Change{Schema: 1, Action: "resume-app-retirement", Principal: job.Origin.Session.User, Expected: entry.Inventory.Revision()}}
	op.Change.Payload, _ = json.Marshal(q)
	c, err := p.Catalog(s)
	if err != nil || p.authorizeApp(c, op) != nil {
		t.Fatal("original cleanup identity", err)
	}
	checkpoint(p.reduceAppRetirementReplay(s, apps, op))
	progress := func(action string) {
		apps, err := p.Apps(s)
		if err != nil {
			t.Fatal(err)
		}
		entry := apps.entries[appKey("tenant", "app")]
		ret, _ := entry.Inventory.Retirement()
		r := AppProgress{Tenant: "tenant", App: "app", Operation: ret.ID, Key: key, Action: action, At: uint64(at), Retire: &AppRetirementProgress{Phase: "delete"}}
		if action == "retire-finish" {
			r.Key = ""
			r.Retire.Phase = ""
		}
		checkpoint(p.reduceAppRetirement(s, r, apps, entry))
	}
	progress("retire-send")
	before := s.Object(key)
	next, result, err := state.ApplyTransactional(s, s.Index()+1, original.Command, p.ValidateManaged, p.Reduce, p.AdmitModule, p.AdmitAppMutation, p.AdmitAppPatch)
	if err != nil || result.Code != state.Applied || !before.Present || next.Object(key).Present {
		t.Fatal("exact original Delete", result, err)
	}
	s = next
	progress("retire-collect")
	progress("retire-finish")
	quiescence, err := p.MoveAppQuiescence(s, job)
	if err != nil || quiescence != "ready" {
		t.Fatal("original source still stuck", quiescence, err)
	}
	if _, err := p.VolumeMovePermit(s, job.Binding.Source.Key, VolumeMovePermitRequest{Selection: job.Selection(), Kind: "fence"}, at); err == nil {
		t.Fatal("original expired move revived")
	}
	if _, found := s.LookupResult(original.Command); !found {
		t.Fatal("original result lost")
	}
	t.Log("exact closed E8 source Delete/retirement resumes to ready; original move remains expired, no native effect/SQL or E8 completion claim")
}
