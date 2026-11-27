// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/ingress"
)

// OS address observations are injected, while signatures, current authority,
// record CAS, Raft reducer/checkpoint validation and public paging are real.
func TestIngressGatewayOperationsRequireExactOwnerIntentAndRetainHistory(t *testing.T) {
	f := newNodeStorageFixture(t)
	change := func(expected uint64, alter func(*NodeGatewaysChange), want state.Code) {
		book, err := f.p.IngressManagement(f.s)
		if err != nil {
			t.Fatal(err)
		}
		old, _ := book.NodeGateways("node-a")
		external := ingress.Gateway{Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.10")}}
		evidence := NodeGatewaysEvidence{Cluster: f.p.Cluster, Reporter: [32]byte(f.node.Public().(ed25519.PublicKey)), Node: "node-a", Request: fmt.Sprintf("user-%d", f.next+1), User: "admin", Key: f.sessions["admin"].Key, Epoch: 1, Expected: expected, At: 2, Previous: old.Configuration, Configuration: MergeNodeGateways(old.Configuration, &external, nil)}
		evidence.Signature = ed25519.Sign(f.node, NodeGatewaysEvidenceBytes(evidence))
		q := NodeGatewaysChange{Node: "node-a", External: &external, Evidence: &evidence}
		if alter != nil {
			alter(&q)
		}
		f.apply("admin", "set-node-gateways", expected, q, want)
	}
	change(0, nil, state.Applied)
	change(0, nil, state.ConditionFailed)
	for _, alter := range []func(*NodeGatewaysChange){func(q *NodeGatewaysChange) { q.Evidence.Request = "different" }, func(q *NodeGatewaysChange) { q.Evidence.Key = f.sessions["manager"].Key }, func(q *NodeGatewaysChange) { q.Evidence.Epoch++ }, func(q *NodeGatewaysChange) { q.Local = &ingress.Gateway{Addresses: q.External.Addresses} }} {
		change(1, alter, state.Invalid)
	}
	f.apply("manager", "set-node-gateways", 1, NodeGatewaysChange{Node: "node-a", External: &ingress.Gateway{}}, state.Forbidden)
	for i := 1; i < 11; i++ {
		change(uint64(i), nil, state.Applied)
	}
	page, err := f.p.IngressPage(f.s, f.sessions["admin"], 2, IngressQuery{Part: "gateways", Node: "node-a"})
	if err != nil || len(page.NodeGateways) != 1 || page.NodeGateways[0].Revision != 11 || page.NodeGateways[0].Source != "cluster" {
		t.Fatal("record revision or desired source", page, err)
	}
	history, err := f.p.IngressPage(f.s, f.sessions["admin"], 2, IngressQuery{Part: "history"})
	if err != nil || len(history.History) != 8 || history.Next == "" {
		t.Fatal("bounded first history page", err)
	}
	previous, _ := json.Marshal(history.History[0].Previous)
	if strings.Contains(string(previous), "Signature") || strings.Contains(string(previous), "Session") {
		t.Fatal("private origin leaked through Previous")
	}
	next, err := f.p.IngressPage(f.s, f.sessions["admin"], 2, IngressQuery{Part: "history", After: history.Next})
	if err != nil || len(next.History) != 3 || next.Next != "" || history.History[7].Request == next.History[0].Request {
		t.Fatal("history continuation replayed/skipped originals", err)
	}
	if _, err = f.p.IngressPage(f.s, f.sessions["admin"], 2, IngressQuery{Part: "history", Tenant: "tenant", After: history.Next}); err == nil {
		t.Fatal("history cursor crossed scope")
	}
	tenant, err := f.p.IngressPage(f.s, f.sessions["manager"], 2, IngressQuery{Part: "history", Tenant: "tenant"})
	if err != nil || len(tenant.History) != 0 {
		t.Fatal("node gateway history leaked to tenant", err)
	}
	if _, err = f.p.IngressPage(f.s, f.sessions["manager"], 2, IngressQuery{Part: "history"}); err == nil {
		t.Fatal("tenant reader listed global history")
	}
	snapshot, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := state.Decode(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.p.IngressManagement(restored); err != nil {
		t.Fatal("original signature/history lost on restore", err)
	}
}

func ingressGatewayOperationCore(t *testing.T, f *backupCoreFixture, id string, expected uint64, configuration ingress.GatewayConfiguration, signer ed25519.PrivateKey, want state.Code) state.Command {
	t.Helper()
	book, err := f.p.IngressManagement(f.s)
	if err != nil {
		t.Fatal(err)
	}
	previous, _ := book.NodeGateways("node-a")
	evidence := NodeGatewaysEvidence{Cluster: f.p.Cluster, Reporter: [32]byte(signer.Public().(ed25519.PublicKey)), Node: "node-a", Request: id, User: "admin", Key: f.session.Key, Epoch: f.s.ModuleEpoch(), Expected: expected, At: 2, Previous: previous.Configuration, Configuration: configuration}
	evidence.Signature = ed25519.Sign(signer, NodeGatewaysEvidenceBytes(evidence))
	q := NodeGatewaysChange{Node: "node-a", External: &configuration.External, Local: &configuration.Local, Evidence: &evidence}
	raw, err := ChangeBytes("set-node-gateways", "admin", expected, q)
	if err != nil {
		t.Fatal(err)
	}
	var change Change
	if err = json.Unmarshal(raw, &change); err != nil {
		t.Fatal(err)
	}
	op := UserOperation{Schema: 1, Session: f.session, At: 2, Epoch: f.s.ModuleEpoch(), RequestID: id, RootRevision: f.s.Object(IngressManagementKey).Revision, Change: change}
	op.Signature = ed25519.Sign(f.admin, OperationBytes(op))
	command, err := op.Command()
	if err != nil {
		t.Fatal(err)
	}
	next, result, err := state.ApplyTransactional(f.s, f.s.Index()+1, command, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
	if err != nil || result.Code != want {
		t.Fatal("original node gateway operation", id, result, want, err)
	}
	f.s = next
	return command
}

// The completed upload is accepted by the original app/standalone reducer.
// No native Task/socket needs to exist for its original fixed port to be held.
func ingressGatewayAcceptedWorkloadCore(t *testing.T, standalone bool, protocol string) (*backupCoreFixture, string) {
	t.Helper()
	f := managedDNSTaskCoreFixture(t)
	name, scope := "held", "held"
	if standalone {
		scope = deployment.StandaloneScopeName("tenant", name)
	}
	raw := []byte(fmt.Sprintf("name: held\nservices:\n  web:\n    image: docker.io/library/php@sha256:%s\n    cpus: '0.1'\n    mem_limit: 16m\n    ports: [{target: 8080, published: '8443', host_ip: 192.0.2.10, protocol: %s}]\n    networks: {lan: {ipv4_address: 10.80.1.40, aliases: [held]}}\n    dns: [10.80.1.1]\n    x-sfc: {node: node-a}\nnetworks:\n  lan: {external: true, name: services}\n", string(bytes.Repeat([]byte{'a'}, 64)), protocol))
	catalog, err := f.p.Catalog(f.s)
	if err != nil {
		t.Fatal(err)
	}
	planning, err := f.p.AppPlanning(f.s, "admin", "tenant")
	if err != nil {
		t.Fatal(err)
	}
	planning.Project, planning.Deployment = scope, "deploy"
	var blueprint deployment.Blueprint
	if standalone {
		blueprint, err = deployment.CompileStandaloneDocument(raw, name, catalog, planning, "entrypoint")
	} else {
		var input deployment.Compose
		input, err = deployment.ParseApp(raw)
		if err == nil {
			blueprint, err = deployment.CompileApp(input, catalog, planning)
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := blueprint.Encode()
	if err != nil {
		t.Fatal(err)
	}
	f.apply("held-upload", "begin-app-upload", 0, AppUploadBegin{Tenant: "tenant", App: scope, Deployment: "deploy", ID: "held-upload", Length: len(encoded), Digest: sha256.Sum256(encoded)}, state.Applied)
	for index, start := 0, 0; start < len(encoded); index, start = index+1, start+deployment.ArtifactPartBytes {
		f.apply(fmt.Sprintf("held-upload-part-%d", index), "put-app-part", uint64(index+1), AppUploadPart{Tenant: "tenant", ID: "held-upload", Index: index, Data: encoded[start:min(len(encoded), start+deployment.ArtifactPartBytes)]}, state.Applied)
	}
	action := "begin-app"
	q := AppBegin{Tenant: "tenant", App: scope, Deployment: "deploy", Upload: "held-upload", Operation: "run-held"}
	if standalone {
		action = "standalone-up"
		q.Standalone = &StandaloneDefinition{Name: name, Lifetime: "temp", Mode: "entrypoint"}
	}
	f.apply("accept-held", action, 0, q, state.Applied)
	task := deployment.ResourceKey("task", "tenant", scope, "web")
	apps, err := f.p.Apps(f.s)
	_, accepted := apps.Execution("tenant", scope)
	if err != nil || !accepted || apps.IsStandalone("tenant", scope) != standalone || f.s.Object(task).Present {
		t.Fatal("fixture did not retain original accepted owner kind before native", err)
	}
	return f, task
}

func TestIngressGatewayReducerRejectsAcceptedAppAndStandaloneHostPorts(t *testing.T) {
	for _, standalone := range []bool{false, true} {
		for _, protocol := range []string{"tcp", "udp"} {
			t.Run(fmt.Sprintf("standalone-%t-%s", standalone, protocol), func(t *testing.T) {
				f, task := ingressGatewayAcceptedWorkloadCore(t, standalone, protocol)
				app := f.s.Object(AppsKey)
				configuration := ingress.GatewayConfiguration{External: ingress.Gateway{Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.0.2.11")}, Ports: []uint16{8443, 9443}, Listeners: []ingress.Listener{{ID: "web", Address: "192.0.2.10:8443", TLS: true, HTTP3: true}}}}
				// A disabled listener retains configuration only, not socket intent.
				ingressGatewayOperationCore(t, f, "gateway-disabled", 0, configuration, f.node, state.Applied)
				configuration.External.Enabled = true
				configuration.External.Listeners[0].Address = "192.0.2.11:9443"
				// Allowed address/port combinations do not reserve a Cartesian
				// product: only this nonconflicting actual listener is held.
				ingressGatewayOperationCore(t, f, "gateway-allowlist", 1, configuration, f.node, state.Applied)
				expected := uint64(2)
				configuration.External.Listeners[0].Address = "192.0.2.10:8443"
				if protocol == "udp" {
					configuration.External.Listeners[0].HTTP3 = false
					ingressGatewayOperationCore(t, f, "gateway-tcp-only", expected, configuration, f.node, state.Applied)
					expected++
					configuration.External.Listeners[0].HTTP3 = true
				}
				before := f.s.Object(IngressManagementKey)
				command := ingressGatewayOperationCore(t, f, "gateway-held-conflict", expected, configuration, f.node, state.Invalid)
				result, found := f.s.LookupResult(command)
				if !found || result.Code != state.Invalid || f.s.Object(IngressManagementKey) != before || f.s.Object(AppsKey) != app || f.s.Object(task).Present {
					t.Fatal("gateway conflict changed original accepted app/standalone or lost rejection", result)
				}
			})
		}
	}
}

func TestIngressGatewayCurrentIdentityReplacesOnlyExactOriginalGatewayClaim(t *testing.T) {
	f, _ := ingressGatewayAcceptedWorkloadCore(t, false, "tcp")
	configuration := ingress.GatewayConfiguration{External: ingress.Gateway{Enabled: true, Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.10")}, Ports: []uint16{8443, 9443}, Listeners: []ingress.Listener{{ID: "web", Address: "192.0.2.10:9443", TLS: true}}}}
	original := ingressGatewayOperationCore(t, f, "gateway-original-owner", 0, configuration, f.node, state.Applied)
	before, err := f.p.IngressManagement(f.s)
	if err != nil {
		t.Fatal(err)
	}
	old := rotateTaskPacketCoreOwner(t, f)
	uses, err := f.p.nodeGatewayHostPortUses(f.s)
	if err != nil || len(uses) != 1 || uses[0].Owner != [32]byte(old.Public().(ed25519.PublicKey)) {
		t.Fatal("identity rotation silently relabeled accepted gateway owner", uses, err)
	}
	rotated, err := f.p.IngressManagement(f.s)
	if err != nil || !buildJSONEqual(before, rotated) {
		t.Fatal("rotation rewrote original accepted gateway", err)
	}
	configuration.External.Listeners[0].TLS = false
	ingressGatewayOperationCore(t, f, "gateway-old-key-denied", 1, configuration, old, state.Invalid)
	ingressGatewayOperationCore(t, f, "gateway-current-stale", 0, configuration, f.node, state.ConditionFailed)
	app := f.s.Object(AppsKey)
	ingressGatewayOperationCore(t, f, "gateway-current-replacement", 1, configuration, f.node, state.Applied)
	uses, err = f.p.nodeGatewayHostPortUses(f.s)
	if err != nil || len(uses) != 1 || uses[0].Owner != [32]byte(f.node.Public().(ed25519.PublicKey)) || f.s.Object(AppsKey) != app {
		t.Fatal("authorized replacement lost current owner or changed original workload", uses, err)
	}
	// Even a valid current-key replacement may not exclude the neighboring
	// accepted app claim at the port requested by the new gateway definition.
	configuration.External.Listeners[0].Address = "192.0.2.10:8443"
	root := f.s.Object(IngressManagementKey)
	ingressGatewayOperationCore(t, f, "gateway-current-app-conflict", 2, configuration, f.node, state.Invalid)
	if f.s.Object(IngressManagementKey) != root || f.s.Object(AppsKey) != app {
		t.Fatal("current key discarded a foreign claim while replacing its gateway")
	}
	receipt, found := f.s.LookupResult(original)
	if !found || receipt.Code != state.Applied {
		t.Fatal("current gateway replacement lost original accepted result")
	}
}
