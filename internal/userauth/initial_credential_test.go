// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/credentials"
)

func TestInitialCredentialPrivateSelectorsNeverRelayOrCrossMethods(t *testing.T) {
	r := credentials.InitialRequest{Schema: 1, Cluster: [32]byte{1}, Owner: [32]byte{2}, Operation: [32]byte{3}, User: "new-user", Username: "new.user", Credential: "first", Profile: "system", Method: access.Password, ExpectedUserRevision: 1, At: 1}
	q := Request{Schema: 1, Method: "initial-credential-stage", Nonce: [32]byte{4}, InitialCredential: &r, Secret: []byte("password")}
	envelope := Envelope{Session: &access.Session{}}
	if !q.validMethodFields() || !q.validCredentialFields(envelope, 1) {
		t.Fatal("private stage rejected")
	}
	for _, edit := range []func(*Request){func(q *Request) { q.Tenant = "tenant" }, func(q *Request) { q.Node = "node-a" }, func(q *Request) { q.Method = "whoami" }, func(q *Request) { q.Method = "initial-credential-observe" }, func(q *Request) { q.InitialCredential = nil }} {
		bad := q
		edit(&bad)
		if bad.validMethodFields() && bad.validCredentialFields(envelope, 1) {
			t.Fatal("mixed private request accepted")
		}
	}
	if q.validCredentialFields(Envelope{}, 1) || q.validCredentialFields(envelope, 3) || q.validCredentialFields(Envelope{Session: envelope.Session, Relay: &Relay{}}, 1) {
		t.Fatal("private input relayed/unauthenticated")
	}
}

func TestInitialIntentPersistsDispatchBeforeEffectAndNeverContainsPrivateMaterial(t *testing.T) {
	home, c, session, issuer := journalFixture(t)
	r := credentials.InitialRequest{Schema: 1, Cluster: c.Cluster, Owner: issuer.Public, Operation: [32]byte{9}, User: "new-user", Username: "new.user", Credential: "first", Profile: "system", Method: access.Token, ExpectedUserRevision: 5, At: time.Now().Unix(), Seconds: 86400}
	intent, err := StageInitialIntent(home, c, session, "issue-first", r)
	if err != nil || intent.Dispatched {
		t.Fatal(err)
	}
	if err = MarkInitialDispatch(home, c, session, "issue-first"); err != nil {
		t.Fatal(err)
	}
	if err = MarkInitialDispatch(home, c, session, "issue-first"); err == nil {
		t.Fatal("second dispatch authorized")
	}
	loaded, err := LoadInitialIntent(home, c, session, "issue-first")
	if err != nil || !loaded.Dispatched || loaded.Request != r || loaded.Fact != nil {
		t.Fatal("unknown outcome reset", err)
	}
	fact, err := credentials.SignInitialFact(r, issuer.Private)
	if err != nil {
		t.Fatal(err)
	}
	if err = RecordInitialFact(home, c, session, "issue-first", fact); err != nil {
		t.Fatal(err)
	}
	loaded, err = LoadInitialIntent(home, c, session, "issue-first")
	if err != nil || loaded.Fact == nil || !loaded.Fact.Verify() {
		t.Fatal(err)
	}
	bad := r
	bad.ExpectedUserRevision++
	if _, err = StageInitialIntent(home, c, session, "issue-first", bad); err == nil {
		t.Fatal("original intent rebound")
	}
	root, err := operationRoot(home, c, session.User, false)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	raw, err := root.ReadFile(initialIntentName("issue-first"))
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range [][]byte{[]byte(`"Token"`), []byte(`"Secret"`), []byte(`"Verifier"`), []byte(`"Password"`)} {
		if bytes.Contains(raw, field) {
			t.Fatal("private field entered provisioning journal")
		}
	}
	var record map[string]any
	if json.Unmarshal(raw, &record) != nil {
		t.Fatal("journal encoding")
	}
	info, err := root.Stat(initialIntentName("issue-first"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("journal permissions", err)
	}
	if _, err = os.Stat(home); err != nil {
		t.Fatal(err)
	}
}
