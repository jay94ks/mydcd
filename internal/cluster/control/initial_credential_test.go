// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/credentials"
)

func TestInitialCredentialRequiresAdminProviderFactAndExactCurrentUser(t *testing.T) {
	f := newBackupCore(t)
	f.apply("empty-user", "put-user", 0, access.User{ID: "new-user", Username: "new.user", Enabled: true}, state.Applied)
	users, _ := f.p.Catalog(f.s)
	u, _ := users.User("new-user")
	r := credentials.InitialRequest{Schema: 1, Cluster: f.p.Cluster, Owner: [32]byte(f.node.Public().(ed25519.PublicKey)), Operation: [32]byte{51}, User: u.ID, Username: u.Username, Credential: "password", Profile: "system", Method: access.Password, ExpectedUserRevision: u.Revision, At: 2}
	if err := f.p.InitialCredentialAllowed(f.s, f.session, 2, r); err != nil {
		t.Fatal(err)
	}
	fact, err := credentials.SignInitialFact(r, f.node)
	if err != nil {
		t.Fatal(err)
	}
	wrong := fact
	wrong.Request.Username = "someone-else"
	f.apply("forged-fact", "issue-initial-credential", u.Revision, wrong, state.Forbidden)
	f.apply("initial-password", "issue-initial-credential", u.Revision, fact, state.Applied)
	users, err = f.p.Catalog(f.s)
	if err != nil {
		t.Fatal(err)
	}
	current, _ := users.User(u.ID)
	if len(current.Credentials) != 1 || !current.Credentials[0].Equal(r.CredentialRecord()) {
		t.Fatal("initial public reference not installed")
	}
	if f.p.InitialCredentialAllowed(f.s, f.session, 2, r) == nil {
		t.Fatal("stale original account accepted")
	}
	encoded, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := state.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.p.Catalog(restored); err != nil {
		t.Fatal("public fact activation snapshot", err)
	}
}
