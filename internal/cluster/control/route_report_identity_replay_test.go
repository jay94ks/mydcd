// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/state"
)

func routeReportRotateOwner(t *testing.T, f *backupCoreFixture, keys map[[32]byte]ed25519.PrivateKey, old [32]byte, seed byte) [32]byte {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
	current := [32]byte(key.Public().(ed25519.PublicKey))
	operation := fmt.Sprintf("report-key-rotation-%d", seed)
	d, _ := f.p.Members(f.s)
	entry, _ := d.Entry("node-a")
	f.apply(operation, "rotate-node-identity", entry.Revision, NodeIdentityChange{ID: "node-a", Operation: operation}, state.Applied)
	proof := lifecycle.IdentityProof{Schema: 1, Cluster: f.p.Cluster, Node: "node-a", Operation: operation, Old: old, New: current, Prepared: [32]byte{seed}}
	proof.OldSignature = ed25519.Sign(keys[old], lifecycle.IdentityProofBytes(proof))
	proof.NewSignature = ed25519.Sign(key, lifecycle.IdentityProofBytes(proof))
	for _, action := range []string{"identity-prepared", "identity-activate", "identity-installed"} {
		private := keys[old]
		if action == "identity-installed" {
			private = key
		}
		d, _ := f.p.Members(f.s)
		r := MemberReport{Schema: 1, Cluster: f.p.Cluster, Reporter: [32]byte(private.Public().(ed25519.PublicKey)), Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(MembersKey).Revision, RequestID: fmt.Sprintf("report-rotation-%s-%d", action, seed), Action: action, Node: "node-a", Operation: operation, Expected: d.Revision}
		if action == "identity-prepared" {
			r.Identity = &proof
		}
		r.Signature = ed25519.Sign(private, MemberReportBytes(r))
		cmd, err := r.Command()
		if err != nil {
			t.Fatal(err)
		}
		next, result, err := state.ApplyTransactional(f.s, f.s.Index()+1, cmd, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
		if err != nil || result.Code != state.Applied {
			t.Fatal(action, result, err)
		}
		f.s = next
	}
	keys[current] = key
	return current
}

func routeReportControlConfiguration(t *testing.T, f *backupCoreFixture) {
	t.Helper()
	_, configuration := cleanupControlIssuer(t, f)
	d, _ := f.p.Members(f.s)
	nodeCoreReport(t, f, MemberReport{Action: "configuration", Node: "node-a", Expected: d.Revision, Configuration: &configuration}, state.Applied)
}

func TestRouteDispatchOriginalAndCurrentIdentityEnvelopesKeepOneLifetime(t *testing.T) {
	for _, originalFirst := range []bool{true, false} {
		t.Run(fmt.Sprint(originalFirst), func(t *testing.T) {
			f, proposal, keys := routeControlOwnersFixture(t)
			routeReportControlConfiguration(t, f)
			approveRouteControl(t, f, proposal)
			ref, nonce, old := originalRouteDispatch(t, f)
			oldCommand, _ := old.Command()
			var originalResult state.Result
			if originalFirst {
				_, originalResult = applyRouteDispatch(t, f, old, state.Applied)
			}
			current := routeReportRotateOwner(t, f, keys, ref.Local.Owner, 187)
			current = routeReportRotateOwner(t, f, keys, current, 188)
			work, err := f.p.RouteWork(f.s, current, RouteWorkRequest{Reference: ref.ID})
			if err != nil {
				t.Fatal(err)
			}
			next := old
			next.Reporter = current
			next.Epoch = work.Epoch
			next.RootRevision = work.AppsRevision
			next.Signature = ed25519.Sign(keys[current], RouteDispatchReportBytes(next))
			applyRouteDispatch(t, f, next, state.Applied)
			if originalFirst {
				_, result := applyRouteDispatch(t, f, old, state.Applied)
				if result != originalResult {
					t.Fatal("original receipt was replaced")
				}
			} else {
				applyRouteDispatch(t, f, old, state.Forbidden)
			}
			work, err = f.p.RouteWork(f.s, current, RouteWorkRequest{Reference: ref.ID})
			before, _ := json.Marshal(old.Dispatch)
			after, _ := json.Marshal(work.Reference.Dispatch)
			if err != nil || !bytes.Equal(before, after) || work.Reference.ID != ref.ID || work.Reference.Lifetime != ref.Lifetime || work.Reference.Generation != ref.Generation {
				t.Fatal("late envelope changed original native lifetime", err)
			}
			permit, err := f.p.RouteNativePermit(f.s, current, RouteNativeRequest{Reference: ref.ID, Nonce: nonce, Operation: 1})
			if err != nil || permit.Journal != old.Dispatch.Journal || permit.Reference != old.Dispatch.Reference {
				t.Fatal("coordination renewal replaced original native Apply", err)
			}
			stored, found := f.s.LookupResult(oldCommand)
			if originalFirst && !found || !originalFirst && found && stored.Code == state.Applied {
				t.Fatal("original unknown was relabeled Applied", stored, found)
			}
		})
	}
}

func TestRouteRetirementOriginalAndCurrentIdentityEnvelopesKeepExactPairedClosure(t *testing.T) {
	for _, originalFirst := range []bool{true, false} {
		t.Run(fmt.Sprint(originalFirst), func(t *testing.T) {
			f, _, reports, keys := routeRetirementFixture(t)
			routeReportControlConfiguration(t, f)
			original := [32]byte(f.node.Public().(ed25519.PublicKey))
			var old RouteRetirementReport
			for _, report := range reports {
				if report.Close.Owner == original {
					old = report
				}
			}
			if old.Close.Owner != original {
				t.Fatal("missing original node-a closure")
			}
			old.RootRevision = f.s.Object(AppsKey).Revision
			old.ResourcesRevision = f.s.Object(ResourcesKey).Revision
			old.Signature = ed25519.Sign(keys[original], RouteRetirementReportBytes(old))
			oldCommand, _ := old.Command()
			var originalResult state.Result
			if originalFirst {
				_, originalResult = applyRouteRetirement(t, f, old, state.Applied)
			}
			current := routeReportRotateOwner(t, f, keys, original, 189)
			current = routeReportRotateOwner(t, f, keys, current, 190)
			work, err := f.p.RouteWork(f.s, current, RouteWorkRequest{Reference: old.Close.Consumer})
			if err != nil {
				t.Fatal(err)
			}
			next := old
			next.Reporter = current
			next.Epoch = work.Epoch
			next.RootRevision = work.AppsRevision
			next.ResourcesRevision = work.ResourcesRevision
			next.Signature = ed25519.Sign(keys[current], RouteRetirementReportBytes(next))
			applyRouteRetirement(t, f, next, state.Applied)
			if originalFirst {
				_, result := applyRouteRetirement(t, f, old, state.Applied)
				if result != originalResult {
					t.Fatal("original closure result was replaced")
				}
			} else {
				applyRouteRetirement(t, f, old, state.Forbidden)
			}
			work, err = f.p.RouteWork(f.s, current, RouteWorkRequest{Reference: old.Close.Consumer})
			before, _ := json.Marshal([]any{old.Dispatch, old.Close, old.Route})
			after, _ := json.Marshal([]any{work.Reference.Dispatch, work.Reference.Closed, work.Reference.RouteClosed})
			if err != nil || !bytes.Equal(before, after) || work.Reference.Dispatch.Reference.Consumer != old.Close.Consumer {
				t.Fatal("late report changed paired closure or original lifetime", err)
			}
			stored, found := f.s.LookupResult(oldCommand)
			if originalFirst && !found || !originalFirst && found && stored.Code == state.Applied {
				t.Fatal("shared positive closure manufactured old Applied result", stored, found)
			}
		})
	}
}
