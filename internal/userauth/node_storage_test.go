// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
)

func TestNodeStorageQuerySelectorsPreserveSystemAuthorization(t *testing.T) {
	_, client, session, issuer := journalFixture(t)
	catalog, err := access.New(client.Self.Public)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err = catalog.Enroll(client.Self.Public, access.User{ID: session.User, Username: session.User, Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: client.Self.Public, Enabled: true}}})
	if err != nil {
		t.Fatal(err)
	}
	session.Scopes = []access.Scope{{Tenant: "*", Actions: []access.Action{access.Read, access.ManageCluster}}}
	session.Signature = ed25519.Sign(issuer.Private, access.SessionBytes(session))
	svc := Service{Policy: control.Policy{Cluster: client.Cluster, Issuers: [][32]byte{issuer.Public}}}
	binding := userBinding{key: session.Key, challenge: [32]byte{1}}
	for _, test := range []struct {
		name string
		q    Request
		want string
	}{
		{"all-roots", Request{Method: "node-storage"}, "ok"},
		{"node-page", Request{Method: "node-storage", Node: "node-a", After: "node-a/hdd"}, "ok"},
		{"invalid-node", Request{Method: "node-storage", Node: "../node-a"}, "denied"},
		{"oversized-cursor", Request{Method: "node-storage", After: strings.Repeat("a", 513)}, "denied"},
		{"tenant-root", Request{Method: "node-storage", Tenant: "tenant"}, "denied"},
		{"space", Request{Method: "node-storage-space", NodeStorage: &control.NodeStorageSelection{Node: "node-a", ID: "hdd"}}, "ok"},
		{"missing-space-selection", Request{Method: "node-storage-space"}, "denied"},
		{"selection-on-other-query", Request{Method: "whoami", NodeStorage: &control.NodeStorageSelection{Node: "node-a", ID: "hdd"}}, "denied"},
		{"node-on-other-query", Request{Method: "whoami", Node: "node-a"}, "denied"},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw, err := requestBody(test.q)
			if err != nil {
				t.Fatal(err)
			}
			e := Envelope{Body: raw, Session: &session, Signature: ed25519.Sign(client.Self.Private, access.RequestBytes(session, binding.challenge, raw))}
			if got := svc.execute(catalog, binding, test.q, e); got.Code != test.want {
				t.Fatal(got.Code, test.want)
			}
		})
	}
	limited := session
	limited.Scopes = []access.Scope{{Tenant: "*", Actions: []access.Action{access.Read}}}
	limited.Signature = ed25519.Sign(issuer.Private, access.SessionBytes(limited))
	q := Request{Method: "node-storage", Node: "node-a"}
	raw, _ := requestBody(q)
	e := Envelope{Body: raw, Session: &limited, Signature: ed25519.Sign(client.Self.Private, access.RequestBytes(limited, binding.challenge, raw))}
	if got := svc.execute(catalog, binding, q, e); got.Code != "denied" {
		t.Fatal("system administrator's limited session bypassed scope", got.Code)
	}
}
