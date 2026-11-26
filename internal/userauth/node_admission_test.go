// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/cluster/membership"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/network/services"
	"github.com/jay94ks/mydcd/internal/tenancy"
)

// The product filter is tested directly. Configuration/ACK/Origin inputs here
// are modeled; these are not authentication, quorum or native closure proofs.
func nodeAdmissionFixture(t *testing.T) (membership.Directory, access.Catalog, [32]byte, [32]byte) {
	t.Helper()
	a := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{31}, 32))
	b := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{32}, 32))
	user := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{33}, 32))
	ak, bk, uk := [32]byte(a.Public().(ed25519.PublicKey)), [32]byte(b.Public().(ed25519.PublicKey)), [32]byte(user.Public().(ed25519.PublicKey))
	cluster := [32]byte{34}
	genesis := config.Peer{ID: "node-a", Key: hex.EncodeToString(ak[:]), Endpoint: "127.0.0.1:9001", Voter: true}
	peer := config.Peer{ID: "node-b", Key: hex.EncodeToString(bk[:]), Endpoint: "127.0.0.1:9002"}
	d, err := membership.New(cluster, genesis)
	if err == nil {
		d, err = d.Invite(peer, "join-b")
	}
	entry, _ := d.Entry(peer.ID)
	if err == nil {
		d, err = d.Dispatch(peer.ID, entry.Revision, entry.Job.Pending.ID, 1, ak)
	}
	entry, _ = d.Entry(peer.ID)
	if err == nil {
		d, err = d.Observe(peer.ID, entry.Revision, entry.Job.Pending.ID, 3, peer)
	}
	entry, _ = d.Entry(peer.ID)
	ack := membership.Ack{Schema: 1, Cluster: cluster, Node: peer.ID, JoinID: entry.JoinID, Key: bk, ConfigurationIndex: 3, AppliedIndex: 3}
	ack.Signature = ed25519.Sign(b, membership.AckBytes(ack))
	if err == nil {
		d, err = d.Installed(ack, entry.Revision)
	}
	if err == nil {
		d, err = d.InstallConfiguration(lifecycle.Configuration{Index: 3, Members: []lifecycle.Member{{ID: genesis.ID, Key: ak, Voter: true}, {ID: peer.ID, Key: bk}}})
	}
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := access.New(uk)
	if err == nil {
		catalog, err = catalog.Enroll(uk, access.User{ID: "admin", Username: "admin", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: uk, Enabled: true}}})
	}
	if err == nil {
		catalog, err = catalog.PutUser("admin", 0, access.User{ID: "ordinary", Username: "ordinary", Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: uk, Enabled: true}}})
	}
	if err != nil {
		t.Fatal(err)
	}
	return d, catalog, ak, bk
}

func TestNodeIngressSeparatesActiveAttestationRecoveryAndOriginalReceipts(t *testing.T) {
	d, catalog, ak, bk := nodeAdmissionFixture(t)
	fresh := Request{Method: "submit", Operation: &control.UserOperation{Change: control.Change{Action: "create-tenant"}}}
	if !nodeIngressAllowed(ak, d, catalog, fresh, Envelope{}, false) {
		t.Fatal("active ingress was denied")
	}
	topology, _ := d.Topology()
	a, _ := topology.Node("node-a")
	d, err := d.BeginNode("node-a", "isolate-a", lifecycle.Isolate, a.Revision, topology.Epoch(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if nodeIngressAllowed(ak, d, catalog, fresh, Envelope{}, false) {
		t.Fatal("isolated ingress admitted new workflow")
	}
	if !nodeIngressAllowed(ak, d, catalog, fresh, Envelope{}, true) {
		t.Fatal("retained original result was hidden")
	}
	if !nodeIngressAllowed(ak, d, catalog, fresh, Envelope{Relay: &Relay{Node: bk}}, false) {
		t.Fatal("isolated consensus leader rejected active ingress attestation")
	}
	if nodeIngressAllowed(bk, d, catalog, fresh, Envelope{Relay: &Relay{Node: ak}}, false) {
		t.Fatal("active leader accepted new workflow from isolated ingress")
	}
	if nodeIngressAllowed(ak, d, catalog, fresh, Envelope{Relay: &Relay{Node: [32]byte{99}}}, false) {
		t.Fatal("unknown relay bypassed ingress admission")
	}
	for _, action := range []string{"restore-node", "resume-node-operation", "down-app", "resume-app-retirement", "cancel-volume-move", "release-volume", "vault-observe-write", "vault-abandon-write", "stop-registry", "begin-volume-move"} {
		request := Request{Method: "resume", Operation: &control.UserOperation{Change: control.Change{Action: action}}}
		if !nodeIngressAllowed(ak, d, catalog, request, Envelope{}, false) {
			t.Fatal("original recovery action blocked", action)
		}
	}
	for _, replacement := range []bool{false, true} {
		change := control.NetworkReconfigure{Target: tenancy.TUNDefinition{Tenant: "tenant", Name: "network", Members: []tenancy.TUNNode{}}}
		if replacement {
			change.Target.Members = []tenancy.TUNNode{{Node: "node-a"}}
		}
		raw, _ := json.Marshal(change)
		request := Request{Method: "submit", Operation: &control.UserOperation{Change: control.Change{Action: "reconfigure-tun-network", Payload: raw}}}
		if nodeIngressAllowed(ak, d, catalog, request, Envelope{}, false) == replacement {
			t.Fatal("network retirement admitted replacement membership", replacement)
		}
	}
	for _, enabled := range []bool{false, true} {
		raw, _ := json.Marshal(services.ManagedDNSDefinition{Schema: 1, Tenant: "tenant", Network: "network", Policy: services.ManagedDNSPolicy{Enabled: enabled}})
		request := Request{Method: "submit", Operation: &control.UserOperation{Change: control.Change{Action: "configure-network-dns", Payload: raw}}}
		if nodeIngressAllowed(ak, d, catalog, request, Envelope{}, false) == enabled {
			t.Fatal("DNS disable and new serving policy were conflated", enabled)
		}
	}
	for _, method := range []string{"app-plan-stream", "checker-source-stage", "checker-module-stage", "registry-credential"} {
		if nodeIngressAllowed(ak, d, catalog, Request{Method: method}, Envelope{}, false) {
			t.Fatal("new data admission on isolated ingress", method)
		}
	}
	for _, method := range []string{"members", "whoami", "result", "app-operation", "checker-source-recover", "checker-module-recover"} {
		if !nodeIngressAllowed(ak, d, catalog, Request{Method: method}, Envelope{}, false) {
			t.Fatal("original read/recovery blocked", method)
		}
	}
	for _, method := range []string{"vault-write-plan", "vault-approval-plan"} {
		request := Request{Method: method}
		if nodeIngressAllowed(ak, d, catalog, request, Envelope{}, false) || !nodeIngressAllowed(ak, d, catalog, request, Envelope{}, true) {
			t.Fatal("original recovery planning and fresh planning were conflated", method)
		}
	}
	if nodeLoginKeyAllowed(ak, d, catalog, "ordinary") || nodeLoginKeyAllowed(ak, d, catalog, "admin") || nodeLoginKeyAllowed(bk, d, catalog, "ordinary") {
		t.Fatal("isolated voter or installed non-voter issued a session")
	}
	for _, method := range []string{"challenge", "credential-challenge"} {
		if nodeIngressAllowed(ak, d, catalog, Request{Method: method, Username: "ordinary"}, Envelope{}, false) || nodeIngressAllowed(ak, d, catalog, Request{Method: method, Username: "admin"}, Envelope{}, false) {
			t.Fatal("credential issuance survived isolation", method)
		}
	}
	if nodeLoginKeyAllowed([32]byte{99}, d, catalog, "admin") {
		t.Fatal("system administrator gave unknown node issuer rights")
	}
}

func TestLoginIngressRequiresActiveInstalledVoterForEveryAuthenticationMethod(t *testing.T) {
	d, catalog, ak, bk := nodeAdmissionFixture(t)
	for _, method := range []string{"challenge", "credential-challenge", "login", "credential-login"} {
		for _, user := range []string{"admin", "ordinary"} {
			request := Request{Method: method, Username: user, Ticket: &Ticket{User: user}}
			if !nodeIngressAllowed(ak, d, catalog, request, Envelope{}, false) || nodeIngressAllowed(bk, d, catalog, request, Envelope{}, false) {
				t.Fatal("voter/non-voter login authority was confused", method, user)
			}
		}
	}
	if !d.MemberKey(bk) || !d.WorkKey(bk) {
		t.Fatal("issuer restriction revoked installed owner/replication authority")
	}
}

func TestNodeApprovalRecoveryRequiresOriginalAppliedReceiptAndOperationSelector(t *testing.T) {
	// Only receipt classification is under test. The fake reducer below models
	// an outcome; VaultApprovalPermit must still verify signatures/grants and
	// join the accepted sync/move and target before any provider access.
	for _, action := range []string{"begin-app", "begin-volume-move"} {
		t.Run(action, func(t *testing.T) {
			origin := control.UserOperation{Schema: 1, Epoch: 1, RequestID: "original", Session: access.Session{Key: [32]byte{1}}, Change: control.Change{Schema: 1, Action: action}}
			var selection *control.AppApprovalSelection
			if action == "begin-app" {
				selection = &control.AppApprovalSelection{Operation: "accepted-sync"}
				// begin-app commands need a canonical AppBegin payload.
				payload, err := json.Marshal(control.AppBegin{})
				if err != nil {
					t.Fatal(err)
				}
				origin.Change.Payload = payload
			}
			command, err := origin.Command()
			if err != nil {
				t.Fatal(err)
			}
			for _, code := range []state.Code{state.Applied, state.Forbidden} {
				empty, _ := state.New("anchor")
				if acceptedNodeApproval(empty, &origin, selection) {
					t.Fatal("missing outcome treated as accepted")
				}
				view, result, err := state.ApplyAdmitted(empty, 1, command, nil, func(state.State, state.Command) (map[string][]byte, state.Code) {
					return map[string][]byte{command.Key: []byte("modeled receipt")}, code
				}, func(state.State, state.Command) bool { return true })
				if err != nil || result.Code != code {
					t.Fatal("modeled original outcome", result, err)
				}
				if acceptedNodeApproval(view, &origin, selection) != (code == state.Applied) {
					t.Fatal("only Applied original permits recovery planning", code)
				}
				changed := origin
				changed.RequestID = "replacement"
				if acceptedNodeApproval(view, &changed, selection) {
					t.Fatal("replacement original adopted another receipt")
				}
				candidate := [32]byte{7}
				if acceptedNodeApproval(view, &origin, &control.AppApprovalSelection{Candidate: &candidate}) {
					t.Fatal("new candidate planning admitted as original recovery")
				}
			}
		})
	}
}
