// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/schema"
)

func TestImageBuildCompactPartPermitMatchesFullDataWithoutRecordingEffects(t *testing.T) {
	for _, chunk := range []uint32{0, imagebuild.UploadPartBytes} {
		for _, record := range []bool{false, true} {
			f, _ := imageBuildFixture(t)
			size := imagebuild.PartBytes
			if chunk != 0 {
				size = imagebuild.UploadPartBytes
			}
			data := bytes.Repeat([]byte{17}, size)
			f.apply("manager", "begin-build-zip-upload", 0, ImageBuildUploadBegin{Tenant: "tenant", Context: "source", Upload: "compact", Length: int64(len(data)), Digest: sha256.Sum256(data), ExpiresAt: 1000, ChunkBytes: chunk}, state.Applied)
			report, full := buildPartProgress(t, f, "compact", 0, data)
			if !record {
				full.Request.Record, full.Request.Proof.Record, full.Request.Proof.Session = false, false, nil
				full.Request.Proof.Signature = ed25519.Sign(f.manager, imagebuild.PartProofBytes(*full.Request.Proof))
			}
			compact, err := full.PartPermit()
			if err != nil {
				t.Fatal(err)
			}
			before, err := state.Encode(f.s)
			if err != nil {
				t.Fatal(err)
			}
			x, err := f.p.ImageBuildIOPermit(f.s, report.Owner, full)
			y, compactErr := f.p.ImageBuildPartPermit(f.s, report.Owner, compact)
			if err != nil || compactErr != nil || !reflect.DeepEqual(x, y) || y.Recorded || y.Scope.ChunkBytes != chunk {
				t.Fatal("full/compact original permit differ", chunk, record, err, compactErr)
			}
			after, err := state.Encode(f.s)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("metadata permit recorded a slot or user/native effect", err)
			}
			raw, err := json.Marshal(compact)
			if err != nil || len(raw) > 16<<10 || bytes.Contains(raw, []byte(`"Data"`)) || bytes.Contains(raw, []byte(`"Request"`)) {
				t.Fatal("ordinary compact fixture contains ZIP transfer data or exceeds its size target", len(raw), err)
			}
			if _, err := schema.Decode[ImageBuildPartPermitCall](append(raw[:len(raw)-1:len(raw)-1], []byte(`,"Data":"cmF3"}`)...)); err == nil {
				t.Fatal("compact canonical decoder accepted raw Data")
			}
			missing := full
			missing.Request.Data = nil
			if _, err := f.p.ImageBuildIOPermit(f.s, report.Owner, missing); err == nil {
				t.Fatal("metadata permit became a full-data transfer")
			}
			changed := full
			changed.Request.Data = bytes.Repeat([]byte{18}, len(data))
			if _, err := changed.PartPermit(); err == nil {
				t.Fatal("compact conversion skipped original body SHA")
			}
			if _, err := f.p.ImageBuildIOPermit(f.s, report.Owner, changed); err == nil {
				t.Fatal("legacy full permit skipped original body SHA")
			}
			if record {
				applyBuildPartProgress(t, f, report, state.Applied)
			} else {
				f.apply("manager", "put-build-zip-part", 1, buildTestPart(t, f, "compact", 0, data), state.Applied)
			}
			x, err = f.p.ImageBuildIOPermit(f.s, report.Owner, full)
			y, compactErr = f.p.ImageBuildPartPermit(f.s, report.Owner, compact)
			if record && (err != nil || compactErr != nil || !reflect.DeepEqual(x, y) || !y.Recorded || y.Expected != 2) || !record && (err == nil || compactErr == nil) {
				t.Fatal("compact ACK recovery changed original recording/legacy CAS", err, compactErr)
			}
			seal := ImageBuildIOCall{Session: full.Session, Tenant: full.Tenant, At: full.At, Request: imagebuild.Transfer{Upload: "compact", Kind: "seal", Expected: 2}}
			if _, err := f.p.ImageBuildIOPermit(f.s, report.Owner, seal); err != nil {
				t.Fatal("original full-data seal permit changed", err)
			}
			if _, err := seal.PartPermit(); err == nil {
				t.Fatal("seal was converted to a metadata part permit")
			}
		}
	}
}

func TestImageBuildCompactPartPermitRejectsOriginalProofAndApprovalChanges(t *testing.T) {
	f, _ := imageBuildFixture(t)
	data := []byte("original part")
	f.apply("manager", "begin-build-zip-upload", 0, ImageBuildUploadBegin{Tenant: "tenant", Context: "source", Upload: "compact-negative", Length: int64(len(data)), Digest: sha256.Sum256(data), ExpiresAt: 1000}, state.Applied)
	report, full := buildPartProgress(t, f, "compact-negative", 0, data)
	original, err := full.PartPermit()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"caller", "tenant", "upload", "user", "session", "approval-substitution", "approval-drop", "scope", "index", "expected", "proof-index", "proof-expected", "length", "digest", "nonce", "record", "signature", "expired", "future", "ceiling"} {
		t.Run(name, func(t *testing.T) {
			q, caller := original, report.Owner
			signProof := func() { q.Proof.Signature = ed25519.Sign(f.manager, imagebuild.PartProofBytes(q.Proof)) }
			switch name {
			case "caller":
				caller[0]++
			case "tenant":
				q.Tenant = "foreign"
			case "upload":
				q.Upload = "another-upload"
			case "user":
				q.Session = f.sessions["admin"]
			case "session":
				q.Session.ID = "another-current-session"
				q.Session.Signature = ed25519.Sign(f.node, access.SessionBytes(q.Session))
			case "approval-substitution", "approval-drop":
				approved, err := access.ApproveSession(q.Session, f.manager)
				if err != nil {
					t.Fatal(err)
				}
				q.Session = approved
				if name == "approval-drop" {
					digest := imagebuild.PartSessionDigest(approved)
					q.Proof.Session = &digest
					signProof()
					q.Session.Approval = nil
				}
			case "scope":
				q.Proof.Scope[0]++
				signProof()
			case "index":
				q.Index++
				q.Proof.Index = q.Index
				signProof()
			case "expected":
				q.Expected++
				q.Proof.Expected = q.Expected
				signProof()
			case "proof-index":
				q.Proof.Index++
			case "proof-expected":
				q.Proof.Expected++
			case "length":
				q.Proof.Length++
				signProof()
			case "digest":
				q.Proof.Digest[0]++ // relay cannot re-sign another user digest
			case "nonce":
				q.Proof.Nonce = [32]byte{}
				signProof()
			case "record":
				q.Proof.Record = false // original Session binding cannot be dropped
				signProof()
			case "signature":
				q.Proof.Signature = append([]byte(nil), q.Proof.Signature...)
				q.Proof.Signature[0] ^= 1
			case "expired":
				q.At = q.Proof.ExpiresAt
			case "future":
				q.Proof.At = q.At + 1
				signProof()
			case "ceiling":
				q.Session.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read}}}
				q.Session.Signature = ed25519.Sign(f.node, access.SessionBytes(q.Session))
				digest := imagebuild.PartSessionDigest(q.Session)
				q.Proof.Session = &digest
				signProof()
			}
			if _, err := f.p.ImageBuildPartPermit(f.s, caller, q); err == nil {
				t.Fatal("compact permit accepted changed original authority", name)
			}
		})
	}
}

func TestImageBuildCompactPartPermitRechecksCurrentMembershipContextAndCredentials(t *testing.T) {
	for _, name := range []string{"membership", "context", "operation", "approval-operation"} {
		t.Run(name, func(t *testing.T) {
			f, spec := imageBuildFixture(t)
			data := []byte("current authority")
			f.apply("manager", "begin-build-zip-upload", 0, ImageBuildUploadBegin{Tenant: "tenant", Context: "source", Upload: "compact-current", Length: int64(len(data)), Digest: sha256.Sum256(data), ExpiresAt: 1000}, state.Applied)
			report, full := buildPartProgress(t, f, "compact-current", 0, data)
			q, err := full.PartPermit()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.p.ImageBuildPartPermit(f.s, report.Owner, q); err != nil {
				t.Fatal("current compact success control", err)
			}
			switch name {
			case "membership":
				admin := f.sessions["admin"]
				admin.Scopes = append([]access.Scope(nil), admin.Scopes...)
				admin.Scopes[0].Actions = append(append([]access.Action(nil), admin.Scopes[0].Actions...), access.ManageMembers)
				admin.Signature = ed25519.Sign(f.node, access.SessionBytes(admin))
				f.sessions["admin"] = admin
				catalog, _ := f.p.Catalog(f.s)
				member, _ := catalog.Membership("tenant", "manager")
				f.apply("admin", "set-membership", member.Revision, access.Membership{Tenant: "tenant", User: "manager", Role: access.Viewer, Enabled: true}, state.Applied)
			case "context":
				spec.Dockerfile = "changed/Dockerfile"
				f.apply("manager", "put-build-context", 1, ImageBuildContextPut{spec}, state.Applied)
			case "operation", "approval-operation":
				catalog, _ := f.p.Catalog(f.s)
				u, _ := catalog.User("manager")
				approver := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{71}, 32))
				if name == "operation" {
					u.Credentials[0].Operations = []string{"image-builds"}
				} else {
					u.Credentials = append(u.Credentials, access.Credential{ID: "approval", Method: access.PrivateKey, PublicKey: [32]byte(approver.Public().(ed25519.PublicKey)), Enabled: true, Operations: []string{"image-builds"}})
				}
				expected := u.Revision
				u.Revision = 0
				f.apply("admin", "put-user", expected, u, state.Applied)
				catalog, _ = f.p.Catalog(f.s)
				u, _ = catalog.User("manager")
				q.Session.AccountRevision = u.Revision
				q.Session.Signature = ed25519.Sign(f.node, access.SessionBytes(q.Session))
				if name == "approval-operation" {
					q.Session, err = access.ApproveSession(q.Session, approver)
					if err != nil {
						t.Fatal(err)
					}
				}
				digest := imagebuild.PartSessionDigest(q.Session)
				q.Proof.Session = &digest
				q.Proof.Signature = ed25519.Sign(f.manager, imagebuild.PartProofBytes(q.Proof))
			}
			if _, err := f.p.ImageBuildPartPermit(f.s, report.Owner, q); err == nil {
				t.Fatal("compact permit bypassed current revocation", name)
			}
		})
	}
}
