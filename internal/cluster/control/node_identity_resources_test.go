// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
)

// Extend the existing accepted Task/network fixture rather than validating
// rotation only against an empty resource registry. Native observations and
// installed configuration remain modeled inputs; no actual TLS/SDK is claimed.
func TestIdentityActivationPreservesLiveAppResourcesAndOriginalVaultIssuer(t *testing.T) {
	f := managedDNSTaskCoreFixture(t)
	for _, scope := range []string{"", "tenant"} {
		resources, err := f.p.Resources(f.s)
		if err != nil {
			t.Fatal(err)
		}
		limit, _ := resources.Quotas.Limit(scope, "node-a")
		expected := limit.Revision
		limit.Revision = 0
		limit.MaxConsumers = 64
		limit.MaxIngressInstances, limit.MaxIngressListeners = 1, 1
		limit.MaxIngressRequests, limit.MaxIngressConnections = 2, 8
		limit.IngressBufferBytes = 128 << 10
		f.apply("identity-ingress-budget-"+scope, "set-node-quota", expected, limit, state.Applied)
	}
	managedDNSTaskCoreBegin(t, f, "identity-app", "10.80.1.41", "identity-app", func(input *deployment.Compose, _ *deployment.PlanningContext) {
		service := input.Services["web"]
		service.Sfc.Node, service.Sfc.Nodes, service.Sfc.PerNode = "", []string{"node-a"}, 1
		attachment := service.Networks["lan"]
		attachment.IPv4 = ""
		service.Networks["lan"] = attachment
		input.Services["web"] = service
		d := &deployment.IngressDeclaration{Node: "node-a", Host: "identity.internal.example", Listeners: []deployment.ListenerDeclaration{{Address: "127.0.0.1:18081"}}, Runtime: deployment.IngressRuntime{MaxRequests: 2, MaxConnections: 8, MaxHeaderBytes: 4096, MaxBodyBytes: 1 << 20, BufferBytes: 128 << 10, RequestTimeoutMS: 5000, DialTimeoutMS: 1000, ResponseHeaderTimeoutMS: 2000, HealthIntervalMS: 100}}
		d.Backend.Service, d.Backend.Network, d.Backend.Port, d.Backend.HealthPath = "web", "lan", 8080, "/readyz"
		input.Sfc.Ingress = d
	})
	apps, err := f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	execution, _ := apps.Execution("tenant", "identity-app")
	for _, step := range execution.Steps() {
		if step.Kind != "task" && step.Kind != "ingress" {
			managedDNSTaskCoreSubmit(t, f, "identity-app", step.Key, true, state.Applied)
			continue
		}
		cmd := managedDNSTaskCoreSubmit(t, f, "identity-app", step.Key, false, state.Applied)
		managedDNSTaskCoreProgress(t, f, "identity-app", "collect", step.Key, nil)
		if step.Kind == "task" {
			managedDNSTaskCoreProgress(t, f, "identity-app", "bind-inputs", step.Key, nil)
		}
		apps, err = f.p.Apps(f.s)
		if err != nil {
			t.Fatal(err)
		}
		current, _ := apps.Execution("tenant", "identity-app")
		stage, _ := current.Stage(step.Key)
		if stage.Result == nil {
			t.Fatal("missing original step result", step.Key)
		}
		// The original Task must hold its actual accepted inputs before its
		// modeled readiness can satisfy the following Ingress dependency.
		observation := deployment.Observation{Cluster: f.p.Cluster, Plan: current.Blueprint().Digest(), Operation: current.ActiveOperation(), Key: step.Key, Native: "mock-native-identity-app", Owner: step.Owner, Command: state.Digest(cmd), Generation: stage.Result.Generation, Revision: stage.Result.Revision, Sequence: 1, At: 10, Applied: true, Healthy: true}
		if step.Kind == "ingress" {
			// Dynamic ingress readiness attests each original backend's exact
			// committed generation/revision, not just a generic Healthy flag.
			for _, key := range step.Identity {
				backend, ok := current.Stage(key)
				if !ok || backend.Result == nil || backend.Result.Code != state.Applied {
					t.Fatal("missing original dynamic ingress backend result", key)
				}
				observation.IngressBackends = append(observation.IngressBackends, deployment.ObjectRef{Key: key, Generation: backend.Result.Generation, Revision: backend.Result.Revision})
			}
			slices.SortFunc(observation.IngressBackends, func(a, b deployment.ObjectRef) int { return strings.Compare(a.Key, b.Key) })
		}
		observation.Signature = ed25519.Sign(f.node, deployment.ObservationBytes(observation))
		managedDNSTaskCoreProgress(t, f, "identity-app", "observe", step.Key, &observation)
	}
	managedDNSTaskCoreProgress(t, f, "identity-app", "finish", "", nil)
	vault, err := f.p.Vault(f.s)
	if err != nil {
		t.Fatal(err)
	}
	f.apply("identity-live-old-issuer", "vault-set-issuer", vault.Approvals.Revision(), VaultIssuer{Key: f.p.TrustRoot, Enabled: true}, state.Applied)
	vault, err = f.p.Vault(f.s)
	if err != nil {
		t.Fatal(err)
	}
	issuer, found := vault.Approvals.Issuer(f.p.TrustRoot)
	if !found {
		t.Fatal("original issuer missing")
	}
	before, err := f.p.ProjectResources(f.s)
	if err != nil || len(before.Goals) == 0 || len(before.Resources.Networks.AllNetworks()) == 0 || len(before.Resources.Quotas.Reservations()) == 0 {
		t.Fatal("fixture lacks original live Task/network/quota references", err)
	}
	original := map[string]map[string]state.Object{}
	for _, prefix := range []string{"workload/", "network/", "ingress/"} {
		original[prefix] = f.s.Objects(prefix)
	}
	appsRoot, vaultRoot, resourceRoot := f.s.Object(AppsKey), f.s.Object(VaultKey), f.s.Object(ResourcesKey)
	next := rotateRQ9CoreOwner(t, f)
	current := [32]byte(next.Public().(ed25519.PublicKey))
	if f.s.Object(AppsKey) != appsRoot || f.s.Object(VaultKey) == vaultRoot || f.s.Object(ResourcesKey) == resourceRoot {
		t.Fatal("identity switch rewrote app authority or failed atomic quota/issuer publication")
	}
	for prefix, objects := range original {
		if !reflect.DeepEqual(objects, f.s.Objects(prefix)) {
			t.Fatal("identity activation rewrote original native/resource goals", prefix)
		}
	}
	after, err := f.p.ProjectResources(f.s)
	if err != nil || !reflect.DeepEqual(before.Resources.Networks.AllNetworks(), after.Resources.Networks.AllNetworks()) || !reflect.DeepEqual(before.Resources.Quotas.Reservations(), after.Resources.Quotas.Reservations()) {
		t.Fatal("activation lost original live resource projection", err)
	}
	for key, original := range before.Goals {
		if !reflect.DeepEqual(original.Goal, after.Goals[key].Goal) {
			t.Fatal("current serving view rewrote original goal/receipt", key)
		}
	}
	assertBackend := func(projection ResourceProjection, suspended bool) {
		t.Helper()
		count := 0
		for _, goal := range projection.Goals {
			if goal.Ingress == nil {
				continue
			}
			if !goal.Ingress.DynamicBackends {
				t.Fatal("fixture did not exercise retained dynamic backend")
			}
			for _, service := range goal.Ingress.Services {
				for _, backend := range service.Backends {
					count++
					if backend.Suspended != suspended {
						t.Fatal("original backend did not follow current physical-node work eligibility", backend)
					}
				}
			}
		}
		if count != 1 {
			t.Fatal("missing exact original live ingress backend", count)
		}
	}
	assertBackend(before, false)
	assertBackend(after, false)
	foreign := [32]byte{99}
	if after.Resources.Quotas.SameOwner("node-a", current, foreign) || f.p.currentResourceKey(f.s, foreign, true) != ([32]byte{}) {
		t.Fatal("identity lineage adopted an unrelated physical owner")
	}
	// A same-node retained listener still consumes the existing budget. The
	// rotation is not permission to reset demand or accept a second instance.
	limited := after
	users, err := f.p.Catalog(f.s)
	if err != nil {
		t.Fatal(err)
	}
	limit, _ := limited.Resources.Quotas.Limit("tenant", "node-a")
	expected := limit.Revision
	limit.Revision, limit.MaxIngressInstances = 0, 0
	limited.Resources.Quotas, err = limited.Resources.Quotas.Set(users, "admin", expected, limit, limited.Resources.Networks)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.p.projectIngress(f.s, &limited); err == nil {
		t.Fatal("rotation stopped charging the original retained ingress")
	}
	for _, old := range before.Resources.Quotas.Limits() {
		limit, ok := after.Resources.Quotas.Limit(old.Tenant, old.Node)
		if !ok {
			t.Fatal("identity activation dropped quota", old.Node, old.Tenant)
		}
		if old.Node == "node-a" {
			if limit.Owner != current || !after.Resources.Quotas.SameOwner(old.Node, current, old.Owner) {
				t.Fatal("current quota owner no longer accounts original resources", limit)
			}
			limit.Owner, limit.Revision = old.Owner, old.Revision
		}
		if !reflect.DeepEqual(limit, old) {
			t.Fatal("identity activation changed quota capacity/policy", limit, old)
		}
	}
	vault, err = f.p.Vault(f.s)
	oldIssuer, retained := vault.Approvals.Issuer(f.p.TrustRoot)
	newIssuer, installed := vault.Approvals.Issuer(current)
	if err != nil || !retained || oldIssuer != issuer || !installed || newIssuer.Key != current || !newIssuer.Enabled || newIssuer.Policy <= issuer.Policy {
		t.Fatal("current issuer did not preserve accepted original issuer history", err)
	}
	raw, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := state.Decode(raw)
	if err != nil || f.p.ValidateManaged(restored, restored, state.Command{}) != nil {
		t.Fatal("atomic identity/resource/Vault candidate does not survive restore", err)
	}
	encoded, err := state.Encode(restored)
	if err != nil || !bytes.Equal(raw, encoded) {
		t.Fatal("restored original state changed", err)
	}
	// Work eligibility remains current even though original ownership and
	// quota charging survive the identity transition.
	members, err := f.p.Members(f.s)
	if err != nil {
		t.Fatal(err)
	}
	topology, err := members.Topology()
	if err != nil {
		t.Fatal(err)
	}
	node, _ := topology.Node("node-a")
	f.apply("identity-disable-current-work", "isolate-node", node.Revision, NodeLifecycleChange{ID: "node-a", Operation: "identity-disable-current-work", Epoch: topology.Epoch()}, state.Applied)
	suspended, err := f.p.ProjectResources(f.s)
	if err != nil {
		t.Fatal(err)
	}
	assertBackend(suspended, true)
	for prefix, objects := range original {
		if !reflect.DeepEqual(objects, f.s.Objects(prefix)) {
			t.Fatal("current work isolation erased original native resources", prefix)
		}
	}

}
