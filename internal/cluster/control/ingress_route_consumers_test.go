// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/json"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/tenancy"
)

// The actual NativePermit consumer gate must consume the same multi-route
// graph as planning. This is quota metadata, not a native readiness fixture.
func TestIngressMultipleRouteConsumerPermitUsesDistinctBackendEdges(t *testing.T) {
	cluster, owner, anchor := [32]byte{51}, [32]byte{52}, [32]byte{53}
	catalog, _ := access.New(anchor)
	var err error
	catalog, err = catalog.Enroll(anchor, access.User{ID: "admin", Username: "admin", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: anchor, Enabled: true}}})
	if err != nil {
		t.Fatal(err)
	}
	catalog, err = catalog.CreateTenant("admin", "tenant", 0)
	if err != nil {
		t.Fatal(err)
	}
	networks, _ := tenancy.New(cluster)
	quotas, _ := tenancy.NewQuotas(cluster)
	for _, tenant := range []string{"", "tenant"} {
		quotas, err = quotas.Set(catalog, "admin", 0, tenancy.NodeLimit{Tenant: tenant, Node: "node-a", Owner: owner, MaxConsumers: 8}, networks)
		if err != nil {
			t.Fatal(err)
		}
	}
	projection := ResourceProjection{Resources: Resources{Quotas: quotas}, Goals: map[string]deployment.GoalResources{}}
	base := deployment.GoalCommand{Schema: 1, Cluster: cluster, Tenant: "tenant", App: "app", Deployment: "deploy", Node: "node-a", Owner: owner}
	bridgeKey := deployment.ResourceKey("bridge", "tenant", "app", "lan/node-a")
	bridge := base
	bridge.Kind = "bridge"
	projection.Goals[bridgeKey] = deployment.GoalResources{Goal: bridge}
	var followed []string
	for _, instance := range []deployment.TaskInstance{{Service: "web", Node: "node-a", Ordinal: 1}, {Service: "web", Node: "node-a", Ordinal: 2}, {Service: "admin", Node: "node-a"}} {
		var service deployment.ComposeService
		service.MyDC.Node = "node-a"
		id := instance.Service
		if instance.Ordinal > 0 {
			copy := instance
			service.MyDC.Instance = &copy
			id = instance.ResourceID()
		}
		key := deployment.ResourceKey("task", "tenant", "app", id)
		goal := base
		goal.Kind = "task"
		goal.Config, _ = json.Marshal(service)
		goal.Dependencies = []deployment.ObjectRef{{Key: bridgeKey}}
		projection.Goals[key] = deployment.GoalResources{Goal: goal}
		if instance.Ordinal > 0 {
			followed = append(followed, key)
		}
	}
	key := deployment.ResourceKey("ingress", "tenant", "app", "http")
	goal := base
	goal.Kind, goal.Follow = "ingress", followed
	goal.Dependencies = []deployment.ObjectRef{{Key: bridgeKey}, {Key: deployment.ResourceKey("task", "tenant", "app", "admin")}}
	goal.Config, _ = json.Marshal(deployment.IngressDeclaration{Node: "node-a", Routes: []deployment.IngressRouteDeclaration{{ID: "root", Service: "web", Network: "lan"}, {ID: "admin", Service: "admin", Network: "lan"}, {ID: "audit", Service: "web", Network: "lan"}}})
	target := deployment.GoalResources{Goal: goal}
	projection.Goals[key] = target
	usage, err := networkConsumerUsageProjection(projection)
	if err != nil || len(usage[bridgeKey].consumers) != 8 {
		t.Fatal("three Task plus five route/backend edges", usage, err)
	}
	if err := admitIngressConsumers(projection, target); err != nil {
		t.Fatal("exact native permit budget rejected multi-route graph", err)
	}
	limit, _ := quotas.Limit("", "node-a")
	expected := limit.Revision
	limit.Revision, limit.MaxConsumers = 0, 7
	quotas, err = quotas.Set(catalog, "admin", expected, limit, networks)
	if err != nil {
		t.Fatal(err)
	}
	projection.Resources.Quotas = quotas
	if err := admitIngressConsumers(projection, target); err == nil {
		t.Fatal("two routes silently shared one backend lease budget")
	}
}
