// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
)

func uploadCASFixture(t *testing.T) *backupCoreFixture {
	f := newBackupCore(t)
	f.session.Scopes = []access.Scope{{Tenant: "*", Actions: []access.Action{access.Read, access.ManageVolumes, access.ManageCluster, access.Deploy}}}
	f.session.Signature = ed25519.Sign(f.node, access.SessionBytes(f.session))
	return f
}

func signedUploadCAS(t *testing.T, f *backupCoreFixture, id, action string, expected, root uint64, payload any) (UserOperation, state.Command) {
	t.Helper()
	raw, err := ChangeBytes(action, "admin", expected, payload)
	if err != nil {
		t.Fatal(err)
	}
	var change Change
	if err = json.Unmarshal(raw, &change); err != nil {
		t.Fatal(err)
	}
	op := UserOperation{Schema: 1, Session: f.session, At: 2, Epoch: f.s.ModuleEpoch(), RequestID: id, RootRevision: root, Change: change}
	op.Signature = ed25519.Sign(f.admin, OperationBytes(op))
	command, err := op.Command()
	if err != nil {
		t.Fatal(err)
	}
	return op, command
}

func TestUploadCASIndependentRootAndExactUploadRevision(t *testing.T) {
	f := uploadCASFixture(t)
	payload := AppUploadBegin{Tenant: "tenant", App: "app", Deployment: "deploy", ID: "original", Length: 1, Digest: sha256.Sum256([]byte{1})}
	_, original := signedUploadCAS(t, f, "original", "begin-app-upload", 0, 0, payload)
	other := payload
	other.ID = "unrelated"
	f.apply("other", "begin-app-upload", 0, other, state.Applied)
	beforeVolume := f.s.Object(VolumesKey)
	apply := func(c state.Command, want state.Code) state.Result {
		t.Helper()
		next, result, err := state.ApplyAdmitted(f.s, f.s.Index()+1, c, f.p.Validate, f.p.Reduce, f.p.AdmitModule)
		if err != nil || result.Code != want {
			t.Fatal(c.RequestID, result, want, err)
		}
		f.s = next
		return result
	}
	created := apply(original, state.Applied)
	if original.Kind != state.ModuleUpload || f.s.Object(VolumesKey) != beforeVolume || apply(original, state.Applied) != created {
		t.Fatal("upload altered resources or replaced the original result")
	}
	encoded, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	f.s, err = state.Decode(encoded)
	if err != nil || apply(original, state.Applied) != created {
		t.Fatal("snapshot lost original upload receipt", err)
	}
	_, part := signedUploadCAS(t, f, "part", "put-app-part", 1, 0, AppUploadPart{Tenant: "tenant", ID: "original", Index: 0, Data: []byte{1}})
	apply(part, state.Applied)
	_, stale := signedUploadCAS(t, f, "stale-part", "put-app-part", 1, 0, AppUploadPart{Tenant: "tenant", ID: "original", Index: 0, Data: []byte{1}})
	apply(stale, state.ConditionFailed)
	_, duplicate := signedUploadCAS(t, f, "duplicate", "begin-app-upload", 0, 0, payload)
	apply(duplicate, state.ConditionFailed)
	_, abort := signedUploadCAS(t, f, "abort", "abort-app-upload", 2, 0, AppUploadSelection{Tenant: "tenant", ID: "original"})
	apply(abort, state.Applied)
	if apply(original, state.Applied) != created {
		t.Fatal("completed cleanup rewrote original admission")
	}
	wire, err := state.EncodeCommand(original)
	decoded, decodeErr := state.DecodeCommand(wire)
	if err != nil || decodeErr != nil || decoded != original || wire[0] != 1 {
		t.Fatal("schema1 upload command roundtrip", err, decodeErr)
	}
}

func TestUploadCASRejectsForgedModeScopeAndFutureRoot(t *testing.T) {
	f := uploadCASFixture(t)
	payload := AppUploadBegin{Tenant: "tenant", App: "app", Deployment: "deploy", ID: "original", Length: 1, Digest: sha256.Sum256([]byte{1})}
	op, command := signedUploadCAS(t, f, "original", "begin-app-upload", 0, 0, payload)
	for _, scenario := range []string{"kind", "namespace", "actor", "no-admission", "future-root", "epoch", "no-deploy"} {
		t.Run(scenario, func(t *testing.T) {
			c := command
			admit := f.p.AdmitModule
			want := state.Forbidden
			switch scenario {
			case "kind":
				c.Kind = state.Module
			case "namespace":
				c.Key = VolumesKey
			case "actor":
				c.Actor = "anchor"
			case "no-admission":
				admit = nil
			case "future-root":
				_, c = signedUploadCAS(t, f, "future", "begin-app-upload", 0, f.s.Index()+1, payload)
				want = state.ConditionFailed
			case "epoch":
				c.Epoch++
				want = state.Expired
			case "no-deploy":
				bad := op
				bad.Session.Scopes = []access.Scope{{Tenant: "*", Actions: []access.Action{access.Read}}}
				bad.Session.Signature = ed25519.Sign(f.node, access.SessionBytes(bad.Session))
				bad.Signature = ed25519.Sign(f.admin, OperationBytes(bad))
				c, _ = bad.Command()
			}
			next, result, err := state.ApplyAdmitted(f.s, f.s.Index()+1, c, f.p.Validate, f.p.Reduce, admit)
			if err != nil || result.Code != want || next.Object(AppsKey) != f.s.Object(AppsKey) {
				t.Fatal("unadmitted upload changed metadata", result, want, err)
			}
		})
	}
}
