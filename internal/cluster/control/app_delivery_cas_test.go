// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
)

func TestDeliveryReportCASUsesCurrentSignedTargetAndPreservesLegacyRoot(t *testing.T) {
	for _, mode := range []string{"same-target", "legacy-current", "legacy-root", "changed-target", "forged", "mode-tamper", "future-root"} {
		t.Run(mode, func(t *testing.T) {
			f := deliveryControlFixture(t)
			apps, _ := f.p.Apps(f.s)
			d, _ := apps.Delivery("tenant", "source-app")
			report := AppDeliveryProgress{Schema: 1, Kind: "app-delivery", Cluster: f.p.Cluster, Reporter: [32]byte(f.node.Public().(ed25519.PublicKey)), Tenant: "tenant", App: "source-app", Action: "fetch", Expected: d.Revision(), RootRevision: f.s.Object(AppsKey).Revision, Epoch: f.s.ModuleEpoch(), At: 10}
			// Only another upload changes the root. The source app/CD remains exact.
			f.apply("other-input", "begin-app-upload", 0, AppUploadBegin{Tenant: "tenant", App: "other", Deployment: "deploy", ID: "other", Length: 1, Digest: sha256.Sum256([]byte{1})}, state.Applied)
			if mode == "changed-target" {
				deliveryControlProgress(t, f, AppDeliveryProgress{Action: "fetch"}, state.Applied)
			}
			if mode == "future-root" {
				report.RootRevision = f.s.Object(AppsKey).Revision + 1
			}
			if mode == "legacy-current" {
				report.RootRevision = f.s.Object(AppsKey).Revision
			}
			report.TargetCAS = mode != "legacy-root" && mode != "legacy-current" && mode != "mode-tamper"
			report.Signature = ed25519.Sign(f.node, AppDeliveryProgressBytes(report))
			if mode == "forged" {
				report.Signature[0] ^= 1
			}
			if mode == "mode-tamper" {
				report.TargetCAS = true
			}
			command, err := report.Command()
			if err != nil {
				t.Fatal(err)
			}
			before := f.s.Object(AppsKey)
			next, result, err := state.ApplyTransactional(f.s, f.s.Index()+1, command, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
			want := state.ConditionFailed
			if mode == "same-target" || mode == "legacy-current" {
				want = state.Applied
			}
			if mode == "forged" || mode == "mode-tamper" {
				want = state.Forbidden
			}
			if mode == "future-root" {
				want = state.Invalid
			}
			if err != nil || result.Code != want {
				t.Fatal("target CAS", mode, result, err)
			}
			if want != state.Applied && next.Object(AppsKey) != before {
				t.Fatal("rejected target changed app metadata")
			}
			if want == state.Applied {
				a, err := f.p.Apps(next)
				if err != nil {
					t.Fatal(err)
				}
				actual, _ := a.Delivery("tenant", "source-app")
				if _, pending := actual.FetchTicket(); !pending {
					t.Fatal("same source target did not progress")
				}
				originalExecution, _ := d.Inventory().Execution()
				if e, _ := actual.Inventory().Execution(); e.ActiveOperation() != originalExecution.ActiveOperation() {
					t.Fatal("source metadata created an app operation")
				}
			}
		})
	}
}
