// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/imagebuild"
)

func imageBuildOwnerTestReport(t *testing.T, f *nodeStorageFixture, report ImageBuildOwnerReport, want state.Code) {
	t.Helper()
	b, err := f.p.ImageBuilds(f.s)
	if err != nil {
		t.Fatal(err)
	}
	u, ok := b.Upload(report.Tenant, report.Upload)
	if !ok {
		t.Fatal("missing original upload")
	}
	report.Schema, report.Cluster, report.Owner = 1, f.p.Cluster, u.Scope.Root.Key
	report.Expected, report.RootRevision, report.Epoch = u.Revision, f.s.Object(ImageBuildKey).Revision, f.s.ModuleEpoch()
	report.Signature = ed25519.Sign(f.node, ImageBuildOwnerReportBytes(report))
	cmd, err := report.Command()
	if err != nil {
		t.Fatal(err)
	}
	next, result, err := state.ApplyAdmitted(f.s, f.s.Index()+1, cmd, f.p.Validate, f.p.Reduce, f.p.AdmitModule)
	if err != nil || result.Code != want {
		t.Fatal(report.Action, result, want, err)
	}
	f.s = next
}

func TestImageBuildExpiryIsSignedFixedInputBeforeReclaim(t *testing.T) {
	f, _ := imageBuildFixture(t)
	data := []byte("original")
	f.apply("manager", "begin-build-zip-upload", 0, ImageBuildUploadBegin{Tenant: "tenant", Context: "source", Upload: "expiry", Length: int64(len(data)), Digest: sha256.Sum256(data), ExpiresAt: 1000}, state.Applied)
	part := buildTestPart(t, f, "expiry", 0, data)
	f.apply("manager", "put-build-zip-part", 1, part, state.Applied)
	b, _ := f.p.ImageBuilds(f.s)
	u, _ := b.Upload("tenant", "expiry")
	fact := imagebuild.ExpiryReceipt{Schema: 1, Scope: u.Scope.Hash(), At: 999}
	fact.Signature = ed25519.Sign(f.node, imagebuild.ExpiryReceiptBytes(fact))
	imageBuildOwnerTestReport(t, f, ImageBuildOwnerReport{Tenant: "tenant", Upload: "expiry", Action: "expired", Expiry: &fact}, state.Forbidden)
	fact.At = 1000
	fact.Signature = ed25519.Sign(f.node, imagebuild.ExpiryReceiptBytes(fact))
	imageBuildOwnerTestReport(t, f, ImageBuildOwnerReport{Tenant: "tenant", Upload: "expiry", Action: "expired", Expiry: &fact}, state.Applied)
	b, _ = f.p.ImageBuilds(f.s)
	u, _ = b.Upload("tenant", "expiry")
	if !u.Closed || u.Revision != 3 || u.Received != 0 || u.Expiry == nil || u.ExpiryReceived != 1 || u.Reclaimed != nil || b.storedBytes("tenant") != int64(len(data)) {
		t.Fatal("expiry fabricated reclamation or lost original evidence")
	}
	for _, obj := range f.s.Objects(buildPartPrefix("tenant", "expiry")) {
		if obj.Present {
			t.Fatal("expired shared part retained as live")
		}
	}
	f.apply("manager", "put-build-zip-part", u.Revision, part, state.ConditionFailed)
	reclaimed := imagebuild.ReclaimReceipt{Schema: 1, Scope: u.Scope.Hash(), Native: sha256.Sum256([]byte("injected actual native closure")), At: 1001}
	reclaimed.Signature = ed25519.Sign(f.node, imagebuild.ReclaimReceiptBytes(reclaimed))
	imageBuildOwnerTestReport(t, f, ImageBuildOwnerReport{Tenant: "tenant", Upload: "expiry", Action: "reclaimed", Reclaimed: &reclaimed}, state.Applied)
	b, _ = f.p.ImageBuilds(f.s)
	u, _ = b.Upload("tenant", "expiry")
	if u.Reclaimed == nil || b.storedBytes("tenant") != 0 {
		t.Fatal("actual owner closure did not return stored byte budget")
	}
	raw, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := state.Decode(raw)
	if err != nil || f.p.Validate(state.State{}, restored, state.Command{}) != nil {
		t.Fatal("expiry/closure restore", err)
	}
}

func TestImageBuildRetainedVersionMustBeExplicitlyDeletedBeforeOwnerGC(t *testing.T) {
	f, _ := imageBuildFixture(t)
	data := []byte("original")
	f.apply("manager", "begin-build-zip-upload", 0, ImageBuildUploadBegin{Tenant: "tenant", Context: "source", Upload: "retained", Length: int64(len(data)), Digest: sha256.Sum256(data), ExpiresAt: 1000}, state.Applied)
	f.apply("manager", "put-build-zip-part", 1, buildTestPart(t, f, "retained", 0, data), state.Applied)
	seal := buildTestSeal(t, f, "retained")
	f.apply("manager", "upload-build-zip", 2, ImageBuildZIPConsume{Tenant: "tenant", ID: "source", Upload: "retained", Fact: seal}, state.Applied)
	b, _ := f.p.ImageBuilds(f.s)
	u, _ := b.Upload("tenant", "retained")
	fact := imagebuild.ReclaimReceipt{Schema: 1, Scope: u.Scope.Hash(), Version: u.Version, Native: sha256.Sum256([]byte("native")), At: 3}
	fact.Signature = ed25519.Sign(f.node, imagebuild.ReclaimReceiptBytes(fact))
	imageBuildOwnerTestReport(t, f, ImageBuildOwnerReport{Tenant: "tenant", Upload: "retained", Action: "reclaimed", Reclaimed: &fact}, state.Forbidden)
	f.apply("manager", "delete-build-version", 2, ImageBuildVersionSelection{Tenant: "tenant", ID: u.Version}, state.ConditionFailed)
	f.apply("manager", "delete-build-version", 1, ImageBuildVersionSelection{Tenant: "tenant", ID: u.Version}, state.Applied)
	b, _ = f.p.ImageBuilds(f.s)
	if b.ArtifactReferenced(u) {
		t.Fatal("deleted version remains an active consumer")
	}
	imageBuildOwnerTestReport(t, f, ImageBuildOwnerReport{Tenant: "tenant", Upload: "retained", Action: "reclaimed", Reclaimed: &fact}, state.Applied)
	f.apply("manager", "delete-build-context", 1, ImageBuildSelection{Tenant: "tenant", ID: "source"}, state.Applied)
	f.apply("manager", "delete-image-build-policy", 1, ImageBuildSelection{Tenant: "tenant"}, state.Applied)
	b, _ = f.p.ImageBuilds(f.s)
	if b.RootReferences(u.Scope.Root) != 0 {
		t.Fatal("retired/reclaimed metadata still holds live root refs")
	}
	if f.p.Validate(state.State{}, f.s, state.Command{}) != nil {
		t.Fatal("deleted version/retained original restore")
	}
}
