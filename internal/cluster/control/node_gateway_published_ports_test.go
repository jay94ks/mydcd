// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/ingress"
	"github.com/jay94ks/seafield/internal/workload"
)

func gatewayPortConfiguration(http3 bool) ingress.GatewayConfiguration {
	return ingress.GatewayConfiguration{External: ingress.Gateway{Enabled: true, Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.0.2.11")}, Ports: []uint16{8443, 9443}, Listeners: []ingress.Listener{{ID: "outside", Address: "192.0.2.10:8443", TLS: true, HTTP3: http3}}}, Local: ingress.Gateway{Enabled: true, Addresses: []netip.Addr{netip.MustParseAddr("198.51.100.10")}, Ports: []uint16{8080}, Listeners: []ingress.Listener{{ID: "inside", Address: "198.51.100.10:8080"}}}}
}
func gatewayComposePortUse(t *testing.T, key, node, host, published, protocol string) deployment.HostPortUse {
	t.Helper()
	ports, err := workload.NormalizePublishedPorts([]workload.PublishedPort{{Target: 8080, HostIP: host, Published: published, Protocol: protocol}})
	if err != nil {
		t.Fatal(err)
	}
	return deployment.HostPortUse{Key: key, Node: node, Owner: [32]byte{22}, Ports: ports}
}
func requireGatewayPortConflict(t *testing.T, current []deployment.HostPortUse, candidate deployment.HostPortUse) {
	t.Helper()
	err := deployment.CheckHostPortUses(current, candidate)
	var input *deployment.InputError
	if !errors.As(err, &input) || input.Code != "HOST_PORT_CONFLICT" || input.Path != candidate.Key {
		t.Fatal("expected same namespace host-port conflict", err)
	}
}

func TestNodeGatewayHostPortsShareComposeNamespaceTCPAndHTTP3(t *testing.T) {
	owner := [32]byte{21}
	configuration := gatewayPortConfiguration(true)
	gateway, err := nodeGatewayHostPortUse("node-a", owner, configuration)
	if err != nil || len(gateway.Ports) != 3 || gateway.Key != IngressManagementKey+"/node-gateways/node-a" || gateway.Owner != owner || gateway.Node != "node-a" {
		t.Fatal(gateway, err)
	}
	for _, key := range []string{deployment.ResourceKey("task", "tenant", "app", "web"), deployment.ResourceKey("task", "other", deployment.StandaloneScopeName("other", "shell"), "web")} {
		for _, protocol := range []string{"tcp", "udp"} {
			requireGatewayPortConflict(t, []deployment.HostPortUse{gateway}, gatewayComposePortUse(t, key, "node-a", "192.0.2.10", "8443", protocol))
			requireGatewayPortConflict(t, []deployment.HostPortUse{gateway}, gatewayComposePortUse(t, key, "node-a", "0.0.0.0", "8443", protocol))
			requireGatewayPortConflict(t, []deployment.HostPortUse{gateway}, gatewayComposePortUse(t, key, "node-a", "", "8443", protocol))
		}
	}
	// Local HTTP is a TCP listener; merely allowing an address/port does not
	// create their Cartesian-product sockets or reserve unused ranges.
	for _, candidate := range []deployment.HostPortUse{
		gatewayComposePortUse(t, "task/other", "node-a", "198.51.100.10", "8080", "udp"),
		gatewayComposePortUse(t, "task/other", "node-a", "192.0.2.11", "8443", "tcp"),
		gatewayComposePortUse(t, "task/other", "node-a", "192.0.2.10", "9443", "tcp"),
		gatewayComposePortUse(t, "task/other", "node-b", "192.0.2.10", "8443", "tcp"),
		gatewayComposePortUse(t, "task/other", "node-a", "192.0.2.10", "", "tcp"),
		gatewayComposePortUse(t, "task/other", "node-a", "192.0.2.10", "8443-8445", "tcp"),
	} {
		if err = deployment.CheckHostPortUses([]deployment.HostPortUse{gateway}, candidate); err != nil {
			t.Fatal("nonconflicting/Docker-selected port was reserved", err)
		}
	}
	requireGatewayPortConflict(t, []deployment.HostPortUse{gateway}, gatewayComposePortUse(t, "task/other", "node-a", "198.51.100.10", "8080", "tcp"))
	configuration.External.Listeners[0].HTTP3 = false
	httpOnly, err := nodeGatewayHostPortUse("node-a", owner, configuration)
	if err != nil {
		t.Fatal(err)
	}
	if err = deployment.CheckHostPortUses([]deployment.HostPortUse{httpOnly}, gatewayComposePortUse(t, "task/other", "node-a", "192.0.2.10", "8443", "udp")); err != nil {
		t.Fatal("HTTP-only gateway reserved UDP", err)
	}
	configuration.External.Enabled = false
	localOnly, err := nodeGatewayHostPortUse("node-a", owner, configuration)
	if err != nil || len(localOnly.Ports) != 1 {
		t.Fatal("disabled external listeners retained desired socket intent", localOnly, err)
	}
	configuration.Local.Enabled = false
	disabled, err := nodeGatewayHostPortUse("node-a", owner, configuration)
	if err != nil || len(disabled.Ports) != 0 {
		t.Fatal(disabled, err)
	}
}

func TestNodeGatewayHostPortsSharedMappingsAndExactSelfClaim(t *testing.T) {
	owner := [32]byte{21}
	configuration := gatewayPortConfiguration(true)
	gateway, err := nodeGatewayHostPortUse("node-a", owner, configuration)
	if err != nil {
		t.Fatal(err)
	}
	// Reprojecting or replacing the one gateway's listener metadata is the
	// SAME resource. Its current control CAS/authority still runs separately.
	configuration.External.Listeners[0].ID = "renamed-listener"
	replacement, err := nodeGatewayHostPortUse("node-a", owner, configuration)
	if err != nil || deployment.CheckHostPortUses([]deployment.HostPortUse{gateway}, replacement) != nil {
		t.Fatal("exact original gateway competed with itself", err)
	}
	foreign := replacement
	foreign.Owner = [32]byte{23}
	requireGatewayPortConflict(t, []deployment.HostPortUse{gateway}, foreign)
	foreign = replacement
	foreign.Key = "forged-gateway"
	requireGatewayPortConflict(t, []deployment.HostPortUse{gateway}, foreign)
	for _, app := range []string{"first", "second"} {
		declaration := deployment.IngressDeclaration{Listeners: []deployment.ListenerDeclaration{{Shared: "outside"}}}
		raw, _ := json.Marshal(declaration)
		shared, err := deployment.StepHostPortUse(deployment.Step{Key: deployment.ResourceKey("ingress", "tenant", app, "http"), Kind: "ingress", Node: "node-a", Owner: owner, Goal: raw})
		if err != nil || len(shared.Ports) != 0 || deployment.CheckHostPortUses([]deployment.HostPortUse{gateway}, shared) != nil {
			t.Fatal("shared app route created a competing socket claim", err)
		}
	}
	// A matching public listener name never turns an independent direct socket
	// into a shared claim; it must still conflict with the managed gateway.
	direct, err := deployment.IngressHostPortUse(deployment.ResourceKey("ingress", "tenant", "direct", "http"), "node-a", owner, deployment.IngressDeclaration{Listeners: []deployment.ListenerDeclaration{{Address: "192.0.2.10:8443"}}})
	if err != nil {
		t.Fatal(err)
	}
	requireGatewayPortConflict(t, []deployment.HostPortUse{gateway}, direct)
	// Conversion owns its result and cannot change the committed configuration.
	gateway.Ports[0].Published = "1"
	again, err := nodeGatewayHostPortUse("node-a", owner, configuration)
	if err != nil || !slices.Equal(again.Ports, replacement.Ports) {
		t.Fatal("projection aliased committed gateway configuration", err)
	}
}

// All acceptance, original signatures, checkpoint validation, projection and
// conflict rejection below use the existing actual reducer/FSM fixture. Only
// numeric OS address observations in NodeGatewaysEvidence are injected.
func TestNodeGatewayHostPortsCommittedProjectionRejectsConflictingUpdateAndRestores(t *testing.T) {
	f := managedDNSTaskCoreFixture(t)
	appPort := gatewayComposePortUse(t, deployment.ResourceKey("task", "tenant", "held", "web"), "node-a", "192.0.2.10", "9443", "tcp")
	managedDNSTaskCoreBegin(t, f, "held", "10.80.1.40", "held", func(input *deployment.Compose, _ *deployment.PlanningContext) {
		service := input.Services["web"]
		service.Ports = appPort.Ports
		input.Services["web"] = service
	})
	originalApp := f.s.Object(AppsKey)
	update := func(id string, expected uint64, configuration ingress.GatewayConfiguration, want state.Code) state.Command {
		t.Helper()
		book, err := f.p.IngressManagement(f.s)
		if err != nil {
			t.Fatal(err)
		}
		previous, _ := book.NodeGateways("node-a")
		evidence := NodeGatewaysEvidence{Cluster: f.p.Cluster, Reporter: [32]byte(f.node.Public().(ed25519.PublicKey)), Node: "node-a", Request: id, User: "admin", Key: f.session.Key, Epoch: f.s.ModuleEpoch(), Expected: expected, At: 2, Previous: previous.Configuration, Configuration: configuration}
		evidence.Signature = ed25519.Sign(f.node, NodeGatewaysEvidenceBytes(evidence))
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
			t.Fatal("original gateway operation", id, result, err)
		}
		f.s = next
		return command
	}
	configuration := gatewayPortConfiguration(true)
	update("gateway-initial", 0, configuration, state.Applied)
	projection, err := f.p.ProjectResources(f.s)
	if err != nil {
		t.Fatal(err)
	}
	var original deployment.HostPortUse
	for _, use := range projection.HostPorts {
		if use.Key == IngressManagementKey+"/node-gateways/node-a" {
			original = use
		}
	}
	if len(original.Ports) != 3 || original.Owner != [32]byte(f.node.Public().(ed25519.PublicKey)) {
		t.Fatal("committed gateway missing exact accepted owner/ports")
	}
	requireGatewayPortConflict(t, projection.HostPorts, gatewayComposePortUse(t, "task/foreign", "node-a", "192.0.2.10", "8443", "tcp"))
	beforeBook, _ := f.p.IngressManagement(f.s)
	// The app has only an accepted original plan, with no native socket yet.
	// Its held fixed publication still denies this signed gateway update in
	// the actual candidate validation transaction, before runtime side effects.
	conflicting := configuration
	conflicting.External.Listeners = slices.Clone(configuration.External.Listeners)
	conflicting.External.Listeners[0].Address = "192.0.2.10:9443"
	denied := update("gateway-port-conflict", 1, conflicting, state.Invalid)
	afterBook, err := f.p.IngressManagement(f.s)
	if err != nil || !buildJSONEqual(beforeBook, afterBook) || f.s.Object(AppsKey) != originalApp {
		t.Fatal("conflicting gateway update changed book/app origin", err)
	}
	rejected, found := f.s.LookupResult(denied)
	if !found || rejected.Code != state.Invalid {
		t.Fatal("known original conflict outcome was lost")
	}
	// Unchanged listener geometry plus changed metadata is a valid update,
	// not another listener claim or a way around the app's publication.
	configuration.External.Listeners[0].ID = "renamed-listener"
	command := update("gateway-metadata-only", 1, configuration, state.Applied)
	receipt, found := f.s.LookupResult(command)
	if !found || receipt.Code != state.Applied || f.s.Object(AppsKey) != originalApp {
		t.Fatal("gateway update altered original accepted app or lost receipt")
	}
	snapshot, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := state.Decode(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	after, err := f.p.nodeGatewayHostPortUses(restored)
	if err != nil || len(after) != 1 || after[0].Key != original.Key || after[0].Owner != original.Owner || !slices.Equal(after[0].Ports, original.Ports) {
		t.Fatal("gateway source/ports changed after restore", err)
	}
	replay, found := restored.LookupResult(command)
	if !found || replay != receipt {
		t.Fatal("restore changed original accepted management receipt")
	}
	replay, found = restored.LookupResult(denied)
	if !found || replay != rejected {
		t.Fatal("restore lost original rejected management receipt")
	}
	// The read-only projection owns its output, including repeated reads from
	// the same committed record. It stores no independent mutable port state.
	after[0].Ports[0].Published = "1"
	current, err := f.p.nodeGatewayHostPortUses(restored)
	if err != nil || len(current) != 1 || !slices.Equal(current[0].Ports, original.Ports) {
		t.Fatal("caller mutated immutable gateway intent", err)
	}
}
