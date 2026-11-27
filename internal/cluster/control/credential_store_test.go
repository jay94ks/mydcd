// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/credentials"
)

func (f *backupCoreFixture) credentialReport(key ed25519.PrivateKey, action string, record *credentials.BuiltinRecord, id string, want state.Code) {
	f.t.Helper()
	report := CredentialStoreReport{Schema: 1, Cluster: f.p.Cluster, Reporter: [32]byte(key.Public().(ed25519.PublicKey)), RootRevision: f.s.Object(CredentialsKey).Revision, Epoch: f.s.ModuleEpoch(), At: 10, Action: action, Record: record, ID: id}
	report.Signature = ed25519.Sign(key, CredentialStoreBytes(report))
	cmd, err := report.Command()
	if err != nil {
		f.t.Fatal(err)
	}
	if want == state.Forbidden {
		if f.p.AdmitModule(f.s, cmd) {
			f.t.Fatal("report admitted")
		}
	} else if !f.p.AdmitModule(f.s, cmd) {
		f.t.Fatal("voter report denied")
	}
	next, r, err := state.ApplyTransactional(f.s, f.s.Index()+1, cmd, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
	if err != nil || r.Code != want {
		f.t.Fatal(action, r.Code, want, err)
	}
	f.s = next
}

func builtinFixtureRecord(t *testing.T, master []byte, r credentials.InitialRequest, material []byte) credentials.BuiltinRecord {
	t.Helper()
	record := credentials.BuiltinRecord{Schema: 1, Cluster: r.Cluster, ID: credentials.BuiltinID(r.Reference()), Reference: r.Reference(), Receipt: r.Receipt(), User: r.User, Credential: r.Credential, Method: r.Method, At: r.At, Sealer: r.Owner}
	record, err := credentials.SealBuiltin(master, record, material)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func TestBuiltinCredentialStoreIsVoterOnlyOnceAndBindsActivation(t *testing.T) {
	f := newBackupCore(t)
	master := bytes.Repeat([]byte{9}, 32)
	material := []byte(`{"private":"verifier-bytes"}`)
	f.apply("empty-user", "put-user", 0, access.User{ID: "new-user", Username: "new.user", Enabled: true}, state.Applied)
	users, _ := f.p.Catalog(f.s)
	u, _ := users.User("new-user")
	owner := [32]byte(f.node.Public().(ed25519.PublicKey))
	r := credentials.InitialRequest{Schema: 1, Cluster: f.p.Cluster, Owner: owner, Operation: [32]byte{52}, User: u.ID, Username: u.Username, Credential: "password", Profile: credentials.BuiltinProfile, Method: access.Password, ExpectedUserRevision: u.Revision, At: 2}
	if err := f.p.InitialCredentialAllowed(f.s, f.session, 2, r); err != nil {
		t.Fatal(err)
	}
	fact, err := credentials.SignInitialFact(r, f.node)
	if err != nil {
		t.Fatal(err)
	}
	// No sealed record yet: the reference cannot be attached.
	f.apply("early", "issue-initial-credential", u.Revision, fact, state.ConditionFailed)

	record := builtinFixtureRecord(t, master, r, material)
	f.credentialReport(f.admin, "put", &record, "", state.Forbidden)
	f.credentialReport(f.node, "put", &record, "", state.Applied)
	f.credentialReport(f.node, "put", &record, "", state.ConditionFailed)
	f.apply("issue", "issue-initial-credential", u.Revision, fact, state.Applied)

	encoded, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, material) {
		t.Fatal("protected material stored in plain text")
	}
	restored, err := state.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	stored, found, err := f.p.BuiltinCredential(restored, record.ID)
	if err != nil || !found || !credentials.SameBuiltin(stored, record) {
		t.Fatal("snapshot lost builtin record", found, err)
	}
	opened, err := credentials.OpenBuiltin(master, stored)
	if err != nil || !bytes.Equal(opened, material) {
		t.Fatal("sealed record does not open", err)
	}
	if _, err = credentials.OpenBuiltin(bytes.Repeat([]byte{8}, 32), stored); err == nil {
		t.Fatal("another master opened the record")
	}

	f.credentialReport(f.admin, "consume", nil, record.ID, state.Forbidden)
	f.credentialReport(f.node, "consume", nil, record.ID, state.Applied)
	f.credentialReport(f.node, "consume", nil, record.ID, state.ConditionFailed)
	stored, _, _ = f.p.BuiltinCredential(f.s, record.ID)
	if !stored.Consumed {
		t.Fatal("consume not recorded")
	}

	// An unreferenced record older than the retention goes on the next put;
	// a referenced one stays.
	orphan := r
	orphan.Operation, orphan.Credential = [32]byte{53}, "spare"
	orphanRecord := builtinFixtureRecord(t, master, orphan, material)
	f.credentialReport(f.node, "put", &orphanRecord, "", state.Applied)
	later := r
	later.Operation, later.Credential, later.At = [32]byte{54}, "later", 2+builtinCredentialRetention+1
	laterRecord := builtinFixtureRecord(t, master, later, material)
	f.credentialReport(f.node, "put", &laterRecord, "", state.Applied)
	if _, found, _ := f.p.BuiltinCredential(f.s, orphanRecord.ID); found {
		t.Fatal("unreferenced old record kept")
	}
	if _, found, _ := f.p.BuiltinCredential(f.s, record.ID); !found {
		t.Fatal("referenced record pruned")
	}
}
