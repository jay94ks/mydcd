// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/nodestorage"
)

// Uses the real admission/reducer/FSM/signature and snapshot boundaries. Native
// receipts are injected here; actual ZIP I/O remains the existing Spool path.
func buildPartProgress(t *testing.T, f *nodeStorageFixture, upload string, index uint32, data []byte) (ImageBuildOwnerReport, ImageBuildIOCall) {
	t.Helper()
	b, err := f.p.ImageBuilds(f.s)
	if err != nil {
		t.Fatal(err)
	}
	u, ok := b.Upload("tenant", upload)
	if !ok {
		t.Fatal("missing original upload")
	}
	proof := imagebuild.PartProof{Schema: 1, Scope: u.Scope.Hash(), Index: index, Length: uint32(len(data)), Digest: sha256.Sum256(data), Expected: u.Revision, At: 2, ExpiresAt: 120, Nonce: [32]byte{1}, Record: true}
	digest := imagebuild.PartSessionDigest(f.sessions["manager"])
	proof.Session = &digest
	proof.Signature = ed25519.Sign(f.manager, imagebuild.PartProofBytes(proof))
	receipt := buildTestPart(t, f, upload, index, data).Receipt
	r := ImageBuildOwnerReport{Schema: 1, Cluster: f.p.Cluster, Owner: u.Scope.Root.Key, Tenant: u.Scope.Tenant, Upload: upload, Action: "part", Expected: u.Revision, RootRevision: f.s.Object(ImageBuildKey).Revision, Epoch: f.s.ModuleEpoch(), Part: &ImageBuildPartProgress{Session: f.sessions["manager"], Proof: proof, Receipt: receipt, At: 2}}
	r.Signature = ed25519.Sign(f.node, ImageBuildOwnerReportBytes(r))
	call := ImageBuildIOCall{Session: f.sessions["manager"], Tenant: u.Scope.Tenant, At: 2, Request: imagebuild.Transfer{Upload: upload, Kind: "part", Expected: u.Revision, Index: index, Data: data, Proof: &proof, Record: true}}
	return r, call
}

func applyBuildPartProgress(t *testing.T, f *nodeStorageFixture, report ImageBuildOwnerReport, want state.Code) state.Command {
	t.Helper()
	cmd, err := report.Command()
	if err != nil {
		t.Fatal(err)
	}
	next, result, err := state.ApplyAdmitted(f.s, f.s.Index()+1, cmd, f.p.Validate, f.p.Reduce, f.p.AdmitModule)
	if err != nil || result.Code != want {
		t.Fatal("owner part progress", result, want, err)
	}
	f.s = next
	return cmd
}

func TestImageBuildOwnerPartProgressExceedsUserLedgerAndRestoresOriginalScope(t *testing.T) {
	f, _ := imageBuildFixture(t)
	parts := state.LedgerLimit + 44
	data := bytes.Repeat([]byte{17}, imagebuild.PartBytes)
	f.apply("manager", "begin-build-zip-upload", 0, ImageBuildUploadBegin{Tenant: "tenant", Context: "source", Upload: "bulk", Length: int64(parts * len(data)), Digest: sha256.Sum256([]byte("whole injected ZIP")), ExpiresAt: 1000}, state.Applied)
	b, _ := f.p.ImageBuilds(f.s)
	begin, _ := b.Upload("tenant", "bulk")
	before, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	userReceipts := buildProgressUserReceipts(t, before)
	var first, last state.Command
	var lastReport ImageBuildOwnerReport
	for index := range parts {
		r, call := buildPartProgress(t, f, "bulk", uint32(index), data)
		permit, err := f.p.ImageBuildIOPermit(f.s, r.Owner, call)
		if err != nil || permit.Recorded {
			t.Fatal("new original part permit", err)
		}
		cmd := applyBuildPartProgress(t, f, r, state.Applied)
		if index == 0 {
			first = cmd
		}
		last, lastReport = cmd, r
		permit, err = f.p.ImageBuildIOPermit(f.s, r.Owner, call)
		if err != nil || !permit.Recorded || permit.Expected != uint64(index+2) {
			t.Fatal("lost ACK did not recover exact original slot", permit, err)
		}
	}
	if f.s.ModuleEpoch() != begin.Begin.Epoch || f.s.Object(buildPartKey("tenant", "bulk", 0)).Value != hex.EncodeToString(lastReport.Part.Receipt.Digest[:]) {
		t.Fatal("bulk progress changed epoch or original slots")
	}
	if _, found := f.s.LookupResult(first); found {
		t.Fatal("old node reports were not collected at the existing bound")
	}
	want, found := f.s.LookupResult(last)
	if !found {
		t.Fatal("latest original ACK not retained")
	}
	raw, _ := json.Marshal(lastReport)
	resolved, err := f.p.ResolveImageBuildOwnerReport(f.s, lastReport.Owner, raw)
	if err != nil || resolved != last {
		t.Fatal("original signed ACK identity changed", err)
	}
	_, replay, err := state.ApplyAdmitted(f.s, f.s.Index()+1, resolved, f.p.Validate, f.p.Reduce, f.p.AdmitModule)
	if err != nil || replay != want {
		t.Fatal("lost ACK replay changed result", replay, err)
	}
	encoded, err := state.Encode(f.s)
	if err != nil || !bytes.Equal(buildProgressUserReceipts(t, encoded), userReceipts) {
		t.Fatal("per-part progress created user ledger entries", err)
	}
	restored, err := state.Decode(encoded)
	if err != nil || f.p.Validate(state.State{}, restored, state.Command{}) != nil {
		t.Fatal("owner progress snapshot invalid", err)
	}
	f.s = restored
	b, _ = f.p.ImageBuilds(f.s)
	u, _ := b.Upload("tenant", "bulk")
	if u.Scope != begin.Scope || !buildJSONEqual(u.Begin, begin.Begin) || !buildJSONEqual(u.Origin, begin.Origin) || u.Revision != uint64(parts+1) || u.Received != uint32(parts) || u.Progress == nil {
		t.Fatal("progress lost signed begin/origin or immutable scope")
	}
	// Existing signed consume remains the only way to create a version.
	seal := buildTestSeal(t, f, "bulk")
	f.apply("manager", "upload-build-zip", u.Revision, ImageBuildZIPConsume{Tenant: "tenant", ID: "source", Upload: "bulk", Fact: seal}, state.Applied)
	encoded, _ = state.Encode(f.s)
	restored, err = state.Decode(encoded)
	if err != nil || f.p.Validate(state.State{}, restored, state.Command{}) != nil {
		t.Fatal("consume after node progress failed restore", err)
	}
}

func buildProgressUserReceipts(t *testing.T, raw []byte) []byte {
	t.Helper()
	var snapshot struct{ Receipts []json.RawMessage }
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatal(err)
	}
	var users []json.RawMessage
	for _, row := range snapshot.Receipts {
		var entry struct{ Actor string }
		if err := json.Unmarshal(row, &entry); err != nil {
			t.Fatal(err)
		}
		if len(entry.Actor) >= 5 && entry.Actor[:5] == "user/" {
			users = append(users, row)
		}
	}
	if len(users) == 0 {
		t.Fatal("fixture has no original user receipts")
	}
	out, _ := json.Marshal(users)
	return out
}

func TestImageBuildPartProgressRejectsForeignFactsProofChangesAndRevocation(t *testing.T) {
	for _, name := range []string{"user", "session", "approval-substitution", "approval-drop", "tenant", "scope", "owner", "signature", "digest", "index", "expected", "mode", "expired", "root", "context", "membership", "ceiling", "operation", "approval"} {
		t.Run(name, func(t *testing.T) {
			f, spec := imageBuildFixture(t)
			data := []byte("original")
			f.apply("manager", "begin-build-zip-upload", 0, ImageBuildUploadBegin{Tenant: "tenant", Context: "source", Upload: "negative", Length: int64(len(data)), Digest: sha256.Sum256(data), ExpiresAt: 1000}, state.Applied)
			r, call := buildPartProgress(t, f, "negative", 0, data)
			switch name {
			case "user":
				r.Part.Session = f.sessions["admin"]
			case "session":
				r.Part.Session.ID = "other-same-key-session"
				r.Part.Session.Signature = ed25519.Sign(f.node, access.SessionBytes(r.Part.Session))
			case "approval-substitution", "approval-drop":
				approved, err := access.ApproveSession(r.Part.Session, f.manager)
				if err != nil {
					t.Fatal(err)
				}
				if name == "approval-substitution" {
					r.Part.Session = approved
				} else {
					digest := imagebuild.PartSessionDigest(approved)
					r.Part.Proof.Session = &digest
					r.Part.Proof.Signature = ed25519.Sign(f.manager, imagebuild.PartProofBytes(r.Part.Proof))
					// Original issuer signature remains valid when approval is
					// omitted, but the signed part must retain its whole grant.
					r.Part.Session = approved
					r.Part.Session.Approval = nil
				}
			case "tenant":
				r.Tenant = "foreign"
			case "scope":
				r.Part.Proof.Scope[0]++
			case "owner":
				r.Owner[0]++
			case "signature":
				r.Part.Receipt.Signature[0] ^= 1
			case "digest":
				r.Part.Receipt.Digest[0]++
				r.Part.Receipt.Signature = ed25519.Sign(f.node, imagebuild.PartReceiptBytes(r.Part.Receipt))
			case "index":
				r.Part.Proof.Index++
			case "expected":
				r.Part.Proof.Expected++ // owner cannot resign this USER proof
			case "mode":
				r.Part.Proof.Record = false
			case "expired":
				r.Part.At = r.Part.Proof.ExpiresAt
			case "root":
				b, _ := f.p.ImageBuilds(f.s)
				u, _ := b.Upload("tenant", "negative")
				changed := u.Scope
				changed.Root.Generation++
				r.Part.Proof.Scope = changed.Hash()
				r.Part.Proof.Signature = ed25519.Sign(f.manager, imagebuild.PartProofBytes(r.Part.Proof))
			case "context":
				spec.Dockerfile = "other/Dockerfile"
				f.apply("manager", "put-build-context", 1, ImageBuildContextPut{spec}, state.Applied)
			case "membership":
				admin := f.sessions["admin"]
				admin.Scopes = append([]access.Scope(nil), admin.Scopes...)
				admin.Scopes[0].Actions = append(append([]access.Action(nil), admin.Scopes[0].Actions...), access.ManageMembers)
				admin.Signature = ed25519.Sign(f.node, access.SessionBytes(admin))
				f.sessions["admin"] = admin
				users, _ := f.p.Catalog(f.s)
				m, _ := users.Membership("tenant", "manager")
				f.apply("admin", "set-membership", m.Revision, access.Membership{Tenant: "tenant", User: "manager", Role: access.Viewer, Enabled: true}, state.Applied)
			case "ceiling":
				r.Part.Session.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read}}}
				r.Part.Session.Signature = ed25519.Sign(f.node, access.SessionBytes(r.Part.Session))
				digest := imagebuild.PartSessionDigest(r.Part.Session)
				r.Part.Proof.Session = &digest
				r.Part.Proof.Signature = ed25519.Sign(f.manager, imagebuild.PartProofBytes(r.Part.Proof))
			case "operation", "approval":
				approver := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{71}, 32))
				if name == "approval" {
					f.addKey("manager", "approval", [32]byte(approver.Public().(ed25519.PublicKey)), []string{"image-builds"})
				} else {
					f.limitAccount("manager", "image-builds")
				}
				users, _ := f.p.Catalog(f.s)
				u, _ := users.User("manager")
				r.Part.Session.AccountRevision = u.Revision
				r.Part.Session.Signature = ed25519.Sign(f.node, access.SessionBytes(r.Part.Session))
				if name == "approval" {
					approved, err := access.ApproveSession(r.Part.Session, approver)
					if err != nil {
						t.Fatal(err)
					}
					r.Part.Session = approved
				}
				call.Session = r.Part.Session
				digest := imagebuild.PartSessionDigest(r.Part.Session)
				r.Part.Proof.Session = &digest
				r.Part.Proof.Signature = ed25519.Sign(f.manager, imagebuild.PartProofBytes(r.Part.Proof))
				call.Request.Proof = &r.Part.Proof
			}
			r.RootRevision = f.s.Object(ImageBuildKey).Revision
			r.Signature = ed25519.Sign(f.node, ImageBuildOwnerReportBytes(r))
			cmd, err := r.Command()
			if err != nil {
				t.Fatal(err)
			}
			if f.p.AdmitModule(f.s, cmd) {
				t.Fatal("foreign/revoked progress admitted", name)
			}
			if name == "membership" || name == "context" || name == "operation" || name == "approval" {
				if _, err := f.p.ImageBuildIOPermit(f.s, r.Owner, call); err == nil {
					t.Fatal("native I/O reused revoked scope authority")
				}
			}
		})
	}
}

func TestImageBuildPartCheckpointExpiryReclaimAndRestore(t *testing.T) {
	f, _ := imageBuildFixture(t)
	data := []byte("original expired artifact")
	f.apply("manager", "begin-build-zip-upload", 0, ImageBuildUploadBegin{Tenant: "tenant", Context: "source", Upload: "progress-expiry", Length: int64(len(data)), Digest: sha256.Sum256(data), ExpiresAt: 1000}, state.Applied)
	r, call := buildPartProgress(t, f, "progress-expiry", 0, data)
	applyBuildPartProgress(t, f, r, state.Applied)
	b, _ := f.p.ImageBuilds(f.s)
	u, _ := b.Upload("tenant", "progress-expiry")
	expiry := imagebuild.ExpiryReceipt{Schema: 1, Scope: u.Scope.Hash(), At: 1000}
	expiry.Signature = ed25519.Sign(f.node, imagebuild.ExpiryReceiptBytes(expiry))
	imageBuildOwnerTestReport(t, f, ImageBuildOwnerReport{Tenant: "tenant", Upload: "progress-expiry", Action: "expired", Expiry: &expiry}, state.Applied)
	for _, slot := range f.s.Objects(buildPartPrefix("tenant", "progress-expiry")) {
		if slot.Present {
			t.Fatal("expired owner progress retained live part rows")
		}
	}
	check := func(reclaimed bool) {
		t.Helper()
		raw, err := state.Encode(f.s)
		if err != nil {
			t.Fatal(err)
		}
		restored, err := state.Decode(raw)
		if err != nil || f.p.Validate(state.State{}, restored, state.Command{}) != nil {
			t.Fatal("expiry normalization/checkpoint restore", reclaimed, err)
		}
		f.s = restored
		b, _ = f.p.ImageBuilds(f.s)
		u, _ = b.Upload("tenant", "progress-expiry")
		if !u.Closed || u.Received != 0 || u.Revision != 3 || u.ExpiryReceived != 1 || u.Progress == nil || u.Expiry == nil || (u.Reclaimed != nil) != reclaimed || u.Scope.Hash() != r.Part.Proof.Scope {
			t.Fatal("expiry/reclaim lost original checkpoint", u.Revision)
		}
		if _, err := f.p.ImageBuildIOPermit(f.s, r.Owner, call); err == nil {
			t.Fatal("closed original slot ACK became new permission")
		}
	}
	check(false)
	reclaimed := imagebuild.ReclaimReceipt{Schema: 1, Scope: u.Scope.Hash(), Native: sha256.Sum256([]byte("injected actual closure")), At: 1001}
	reclaimed.Signature = ed25519.Sign(f.node, imagebuild.ReclaimReceiptBytes(reclaimed))
	imageBuildOwnerTestReport(t, f, ImageBuildOwnerReport{Tenant: "tenant", Upload: "progress-expiry", Action: "reclaimed", Reclaimed: &reclaimed}, state.Applied)
	check(true)
}

func TestImageBuildPartRecordedReplyRequiresExactConfirmedPart(t *testing.T) {
	f, _ := imageBuildFixture(t)
	data := []byte("reply")
	f.apply("manager", "begin-build-zip-upload", 0, ImageBuildUploadBegin{Tenant: "tenant", Context: "source", Upload: "reply", Length: int64(len(data)), Digest: sha256.Sum256(data), ExpiresAt: 1000}, state.Applied)
	r, call := buildPartProgress(t, f, "reply", 0, data)
	b, _ := f.p.ImageBuilds(f.s)
	u, _ := b.Upload("tenant", "reply")
	legacy := ImageBuildIOResult{Schema: 1, Scope: u.Scope.Hash(), Code: "OK", Part: &r.Part.Receipt}
	if !legacy.Valid(u.Scope, call.Request) {
		t.Fatal("old stage-only reply rejected")
	}
	encoded, _ := json.Marshal(legacy)
	if bytes.Contains(encoded, []byte("Recorded")) || bytes.Contains(encoded, []byte("UploadRevision")) {
		t.Fatal("stage-only reply changed old optional-zero JSON")
	}
	confirmed := legacy
	confirmed.Recorded, confirmed.UploadRevision = true, 2
	if !confirmed.Valid(u.Scope, call.Request) {
		t.Fatal("confirmed exact part rejected")
	}
	for _, edit := range []func(*ImageBuildIOResult){
		func(r *ImageBuildIOResult) { r.UploadRevision = 0 },
		func(r *ImageBuildIOResult) { r.Recorded = false },
		func(r *ImageBuildIOResult) { r.Code = "CONFLICT"; r.Part = nil },
		func(r *ImageBuildIOResult) { part := *r.Part; part.Index++; r.Part = &part },
	} {
		bad := confirmed
		edit(&bad)
		if bad.Valid(u.Scope, call.Request) {
			t.Fatal("unconfirmed or foreign reply accepted")
		}
	}
	call.Request.Record = false
	proof := *call.Request.Proof
	proof.Record = false
	proof.Session = nil
	call.Request.Proof = &proof
	if !legacy.Valid(u.Scope, call.Request) || confirmed.Valid(u.Scope, call.Request) {
		t.Fatal("legacy default silently records progress")
	}
	seal := ImageBuildIOResult{Schema: 1, Scope: u.Scope.Hash(), Code: "OK", Seal: new(imagebuild.SealReceipt), Recorded: true, UploadRevision: 2}
	if seal.Valid(u.Scope, imagebuild.Transfer{Kind: "seal", Upload: u.Scope.Upload, Expected: 1}) {
		t.Fatal("seal exposes part confirmation metadata")
	}
}

func TestImageBuildOwnerReportPreservesOriginalSchemaOneSigningBytes(t *testing.T) {
	current := ImageBuildOwnerReport{Schema: 1, Cluster: [32]byte{1}, Owner: [32]byte{2}, Tenant: "tenant", Upload: "original", Action: "expired", Expected: 2, RootRevision: 7, Epoch: 1, Expiry: &imagebuild.ExpiryReceipt{Schema: 1, Scope: [32]byte{3}, At: 1000}}
	old := struct {
		Schema                        uint8
		Cluster, Owner                [32]byte
		Tenant, Upload, Action        string
		Expected, RootRevision, Epoch uint64
		Expiry                        *imagebuild.ExpiryReceipt  `json:",omitempty"`
		Reclaimed                     *imagebuild.ReclaimReceipt `json:",omitempty"`
		Signature                     []byte
	}{current.Schema, current.Cluster, current.Owner, current.Tenant, current.Upload, current.Action, current.Expected, current.RootRevision, current.Epoch, current.Expiry, nil, nil}
	raw, _ := json.Marshal(old)
	if !bytes.Equal(ImageBuildOwnerReportBytes(current), append([]byte("sfc-imagebuild-owner-report-1\x00"), raw...)) {
		t.Fatal("optional owner part progress changed retained report signing bytes")
	}
}

func TestImageBuildPermitIncludesReportRootOnlyForExplicitRecording(t *testing.T) {
	f, _ := imageBuildFixture(t)
	data := []byte("native part")
	f.apply("manager", "begin-build-zip-upload", 0, ImageBuildUploadBegin{Tenant: "tenant", Context: "source", Upload: "permit-root", Length: int64(len(data)), Digest: sha256.Sum256(data), ExpiresAt: 1000}, state.Applied)
	r, call := buildPartProgress(t, f, "permit-root", 0, data)
	work, err := f.p.ImageBuildIOPermit(f.s, r.Owner, call)
	if err != nil || work.Scope.Hash() != call.Request.Proof.Scope || work.Expected != call.Request.Expected || work.Epoch != f.s.ModuleEpoch() || work.RootRevision != f.s.Object(ImageBuildKey).Revision || work.RootRevision == 0 || work.RootRevision > work.Index {
		t.Fatal("recording permit lost exact report scope/root/CAS", work, err)
	}
	call.Request.Record = false
	proof := *call.Request.Proof
	proof.Record, proof.Session = false, nil
	proof.Signature = ed25519.Sign(f.manager, imagebuild.PartProofBytes(proof))
	call.Request.Proof = &proof
	legacy, err := f.p.ImageBuildIOPermit(f.s, r.Owner, call)
	if err != nil || legacy.RootRevision != 0 || legacy.Recorded {
		t.Fatal("legacy staging acquired owner progress", legacy, err)
	}
	old := struct {
		Schema                 uint8
		Cluster                [32]byte
		Scope                  imagebuild.UploadScope
		Root                   nodestorage.Root
		Expected, Epoch, Index uint64
		Recorded               bool `json:",omitempty"`
	}{legacy.Schema, legacy.Cluster, legacy.Scope, legacy.Root, legacy.Expected, legacy.Epoch, legacy.Index, legacy.Recorded}
	want, _ := json.Marshal(old)
	got, _ := json.Marshal(legacy)
	if !bytes.Equal(want, got) {
		t.Fatal("stage-only permit JSON changed")
	}
}

func TestImageBuildPartReportCASAndLegacyStagingRemainSeparate(t *testing.T) {
	f, spec := imageBuildFixture(t)
	data := bytes.Repeat([]byte{3}, imagebuild.PartBytes*2)
	f.apply("manager", "begin-build-zip-upload", 0, ImageBuildUploadBegin{Tenant: "tenant", Context: "source", Upload: "parallel-progress", Length: int64(len(data)), Digest: sha256.Sum256(data), ExpiresAt: 1000}, state.Applied)
	first, originalCall := buildPartProgress(t, f, "parallel-progress", 0, data[:imagebuild.PartBytes])
	second, _ := buildPartProgress(t, f, "parallel-progress", 1, data[imagebuild.PartBytes:])
	spec.ID = "unrelated-progress"
	f.apply("manager", "put-build-context", 0, ImageBuildContextPut{spec}, state.Applied)
	applyBuildPartProgress(t, f, first, state.ConditionFailed)
	first.RootRevision = f.s.Object(ImageBuildKey).Revision
	first.Signature = ed25519.Sign(f.node, ImageBuildOwnerReportBytes(first))
	applyBuildPartProgress(t, f, first, state.Applied)
	second.RootRevision = f.s.Object(ImageBuildKey).Revision
	second.Signature = ed25519.Sign(f.node, ImageBuildOwnerReportBytes(second))
	applyBuildPartProgress(t, f, second, state.Forbidden)
	second.Expected++ // retaining an old USER proof cannot adopt another CAS
	second.Signature = ed25519.Sign(f.node, ImageBuildOwnerReportBytes(second))
	applyBuildPartProgress(t, f, second, state.Forbidden)
	permit, err := f.p.ImageBuildIOPermit(f.s, first.Owner, originalCall)
	if err != nil || !permit.Recorded || permit.Expected != 2 {
		t.Fatal("original slot ACK not recoverable", permit, err)
	}
	originalCall.Request.Record = false
	proof := *originalCall.Request.Proof
	proof.Record = false
	proof.Session = nil
	proof.Signature = ed25519.Sign(f.manager, imagebuild.PartProofBytes(proof))
	originalCall.Request.Proof = &proof
	if _, err := f.p.ImageBuildIOPermit(f.s, first.Owner, originalCall); err == nil {
		t.Fatal("legacy stale CAS silently adopted owner progress")
	}
	// A fresh legacy stage at the exact current CAS never records a bitmap.
	legacy := buildTestPart(t, f, "parallel-progress", 1, data[imagebuild.PartBytes:])
	f.apply("manager", "put-build-zip-part", 2, legacy, state.Applied)
	encoded, _ := state.Encode(f.s)
	restored, err := state.Decode(encoded)
	if err != nil || f.p.Validate(state.State{}, restored, state.Command{}) != nil {
		t.Fatal("legacy user operation after owner progress lost compatibility", err)
	}
}
