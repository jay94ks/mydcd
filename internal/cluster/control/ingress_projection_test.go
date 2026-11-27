// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/tenancy"
)

func TestManagedIngressProjectionReservesPortsBudgetsAndOriginalLifetime(t *testing.T) {
	owner, anchor := [32]byte{41}, [32]byte{42}
	p := Policy{Cluster: [32]byte{43}, BootstrapKey: anchor, TrustRoot: anchor}
	c, _ := access.New(anchor)
	c, err := c.Enroll(anchor, access.User{ID: "admin", Username: "admin", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: anchor, Enabled: true}}})
	if err != nil {
		t.Fatal(err)
	}
	c, err = c.CreateTenant("admin", "tenant", 0)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := tenancy.New(p.Cluster)
	q, _ := tenancy.NewQuotas(p.Cluster)
	for _, scope := range []string{"", "tenant"} {
		q, err = q.Set(c, "admin", 0, tenancy.NodeLimit{Tenant: scope, Node: "node-a", Owner: owner, Networks: 8, MaxConsumers: 8, MaxIngressInstances: 4, MaxIngressListeners: 8, MaxIngressRequests: 8, MaxIngressConnections: 32, IngressBufferBytes: 512 << 10}, n)
		if err != nil {
			t.Fatal(err)
		}
	}
	put := func(s state.State, key string, goal deployment.GoalCommand) state.State {
		t.Helper()
		raw, _ := json.Marshal(goal)
		cmd := state.Command{Actor: "admin", Epoch: 1, RequestID: fmt.Sprint("fixture-", s.Index()+1), Key: key, Expected: s.Object(key).Revision, Value: string(raw)}
		next, r, e := state.Apply(s, s.Index()+1, cmd)
		if e != nil || r.Code != state.Applied {
			t.Fatal("fixed metadata input", r, e)
		}
		return next
	}
	makeApp := func(s state.State, app, listener string) state.State {
		t.Helper()
		base := deployment.GoalCommand{Schema: 1, Cluster: p.Cluster, Tenant: "tenant", App: app, Deployment: "deploy", Node: "node-a", Owner: owner}
		bridgeKey := deployment.ResourceKey("bridge", "tenant", app, "lan/node-a")
		g := base
		g.Kind = "bridge"
		g.Config = []byte(`{"Network":"lan","MTU":1280,"Pool":{"CIDR":"10.90.0.0/24","Gateway":"10.90.0.1"}}`)
		s = put(s, bridgeKey, g)
		ref := func(key string) deployment.ObjectRef {
			o := s.Object(key)
			return deployment.ObjectRef{Key: key, Generation: o.Generation, Revision: o.Revision}
		}
		taskKey := deployment.ResourceKey("task", "tenant", app, "web")
		g = base
		g.Kind = "task"
		g.Config = []byte(`{"CPUs":"0.1","Memory":"16m","Networks":{"lan":{"IPv4":"10.90.0.2"}},"Sfc":{"Node":"node-a"}}`)
		g.Dependencies = []deployment.ObjectRef{ref(bridgeKey)}
		s = put(s, taskKey, g)
		var d deployment.IngressDeclaration
		d.Node = "node-a"
		d.Host = "app.test"
		d.Listeners = []deployment.ListenerDeclaration{{Address: listener}}
		d.Backend.Service = "web"
		d.Backend.Port = 8080
		d.Backend.HealthPath = "/readyz"
		d.Runtime = deployment.IngressRuntime{MaxRequests: 2, MaxConnections: 8, MaxHeaderBytes: 4096, MaxBodyBytes: 1 << 20, BufferBytes: 128 << 10, RequestTimeoutMS: 5000, DialTimeoutMS: 1000, ResponseHeaderTimeoutMS: 2000, HealthIntervalMS: 100}
		g = base
		g.Kind = "ingress"
		g.Config, _ = json.Marshal(d)
		g.Dependencies = []deployment.ObjectRef{ref(taskKey)}
		return put(s, deployment.ResourceKey("ingress", "tenant", app, "http"), g)
	}
	project := func(s state.State, limits tenancy.Quotas, pending ...deployment.PlannedResource) (ResourceProjection, error) {
		r := ResourceProjection{Resources: Resources{Quotas: limits}, Goals: map[string]deployment.GoalResources{}, MoveHolds: pending}
		for key, o := range s.Objects("") {
			if !o.Present || strings.HasPrefix(key, CatalogKey) {
				continue
			}
			g, e := deployment.DecodeGoalResources(p.Cluster, key, o)
			if e != nil {
				return r, e
			}
			r.Goals[key] = g
		}
		err := p.projectIngress(s, &r)
		return r, err
	}
	s, _ := state.New("admin")
	writes, code := p.checkpoint(s, c)
	if code != state.Applied {
		t.Fatal("catalog checkpoint", code)
	}
	s, applied, err := state.ApplyReduced(s, s.Index()+1, state.Command{Kind: state.Module, Actor: "admin", Epoch: 1, RequestID: "catalog", Key: CatalogKey, Value: "fixture"}, nil, func(state.State, state.Command) (map[string][]byte, state.Code) { return writes, state.Applied })
	if err != nil || applied.Code != state.Applied {
		t.Fatal("catalog fixture", applied, err)
	}
	s = makeApp(s, "first", "127.0.0.1:8081")
	r, err := project(s, q)
	if err != nil {
		t.Fatal("valid original projection", err)
	}
	if err = admitIngressConsumers(r, r.Goals[deployment.ResourceKey("ingress", "tenant", "first", "http")]); err != nil {
		t.Fatal(err)
	}
	// Pending artifacts reserve real endpoint/budget space without publishing
	// a Goal or inventing a native generation. The same cold-replaced resource
	// can keep its port, while another app must not borrow old or future ports.
	firstKey := deployment.ResourceKey("ingress", "tenant", "first", "http")
	var planned deployment.IngressDeclaration
	if json.Unmarshal(r.Goals[firstKey].Goal.Config, &planned) != nil {
		t.Fatal("original ingress declaration")
	}
	hold := deployment.PlannedResource{Origin: [32]byte{9}, Scope: deployment.AppScope{Cluster: p.Cluster, Actor: "admin", Tenant: "tenant", App: "pending", Deployment: "deploy"}, Demand: deployment.ResourceDemand{Key: deployment.ResourceKey("ingress", "tenant", "pending", "http"), Kind: "ingress", Node: "node-a", Owner: owner}}
	hold.Demand.Ingress = &planned
	if _, err = project(s, q, hold); err == nil {
		t.Fatal("pending listener stole active app port")
	}
	// Current and future uses of the same source/consumer share one slot.
	// A different future consumer, or another owner, cannot borrow that slot.
	bridgeKey := deployment.ResourceKey("bridge", "tenant", "first", "lan/node-a")
	taskKeyPending := deployment.ResourceKey("task", "tenant", "first", "web")
	edge := deployment.NetworkConsumerDemand{Source: bridgeKey, Consumer: taskKeyPending + "/" + bridgeKey, Tenant: "tenant", Node: "node-a", Owner: owner}
	consumerView := r
	consumerView.MoveConsumers = []deployment.NetworkConsumerDemand{edge}
	limConsumers, _ := q.Limit("", "node-a")
	revConsumers := limConsumers.Revision
	limConsumers.Revision = 0
	limConsumers.MaxConsumers = 2
	consumerLimits, err := q.Set(c, "admin", revConsumers, limConsumers, n)
	if err != nil {
		t.Fatal(err)
	}
	consumerView.Resources.Quotas = consumerLimits
	if err := admitMoveConsumers(consumerView); err != nil {
		t.Fatal("same desired edge was charged twice", err)
	}
	consumerView.MoveConsumers[0].Consumer = "future-competitor"
	if admitMoveConsumers(consumerView) == nil {
		t.Fatal("pending target consumer bypassed original native budget")
	}
	consumerView.MoveConsumers = []deployment.NetworkConsumerDemand{edge}
	consumerView.MoveConsumers[0].Owner[0]++
	if admitMoveConsumers(consumerView) == nil {
		t.Fatal("foreign owner borrowed source capacity")
	}

	planned.Listeners = []deployment.ListenerDeclaration{{Address: "127.0.0.1:8083"}}
	if _, err = project(s, q, hold); err != nil {
		t.Fatal("disjoint desired endpoint rejected", err)
	}
	limPending, _ := q.Limit("", "node-a")
	revPending := limPending.Revision
	limPending.Revision = 0
	limPending.MaxIngressInstances = 1
	tight, err := q.Set(c, "admin", revPending, limPending, n)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = project(s, tight, hold); err == nil {
		t.Fatal("desired ingress instance bypassed node limit")
	}
	own := hold
	own.Scope.App = "first"
	own.Demand.Key = firstKey
	planned.Listeners = []deployment.ListenerDeclaration{{Address: "0.0.0.0:8081"}}
	if _, err = project(s, tight, own); err != nil {
		t.Fatal("same cold-replaced listener was charged twice", err)
	}
	if _, err = project(makeApp(s, "other", "127.0.0.1:8081"), q, own); err == nil {
		t.Fatal("another app borrowed retained old/future endpoint")
	}
	if _, err = project(makeApp(s, "other", "127.0.0.2:8081"), q, own); err == nil {
		t.Fatal("another app borrowed future wildcard endpoint")
	}
	if _, err = project(makeApp(s, "second", "127.0.0.1:8082"), q); err != nil {
		t.Fatal("distinct original listeners", err)
	}
	if _, err = project(makeApp(s, "second", "0.0.0.0:8081"), q); err == nil {
		t.Fatal("wildcard/node listener conflict accepted")
	}
	for _, mutate := range []func(*tenancy.NodeLimit){func(l *tenancy.NodeLimit) { l.MaxIngressInstances = 0 }, func(l *tenancy.NodeLimit) { l.MaxIngressListeners = 0 }, func(l *tenancy.NodeLimit) { l.MaxIngressRequests = 1 }, func(l *tenancy.NodeLimit) { l.MaxIngressConnections = 7 }, func(l *tenancy.NodeLimit) { l.IngressBufferBytes = 64 << 10 }} {
		lim, _ := q.Limit("", "node-a")
		rev := lim.Revision
		lim.Revision = 0
		mutate(&lim)
		smaller, e := q.Set(c, "admin", rev, lim, n)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = project(s, smaller); e == nil {
			t.Fatal("serving demand exceeded current global budget")
		}
	}
	lim, _ := q.Limit("", "node-a")
	rev := lim.Revision
	lim.Revision = 0
	lim.MaxConsumers = 1
	smaller, err := q.Set(c, "admin", rev, lim, n)
	if err != nil {
		t.Fatal(err)
	}
	r, err = project(s, smaller)
	if err != nil {
		t.Fatal("consumer shrink must retain original desired", err)
	}
	if admitIngressConsumers(r, r.Goals[deployment.ResourceKey("ingress", "tenant", "first", "http")]) == nil {
		t.Fatal("new Ingress bypassed native dependency consumer capacity")
	}
	key := deployment.ResourceKey("ingress", "tenant", "first", "http")
	var g deployment.GoalCommand
	_ = json.Unmarshal([]byte(s.Object(key).Value), &g)
	g.Lifecycle = &schema.Lifecycle{Drain: true, Nonce: [16]byte{1}}
	draining := put(s, key, g)
	lim, _ = q.Limit("", "node-a")
	rev = lim.Revision
	lim.Revision = 0
	lim.MaxIngressInstances = 0
	smaller, _ = q.Set(c, "admin", rev, lim, n)
	if _, err = project(draining, smaller); err == nil {
		t.Fatal("Drain without positive Gone released ingress reservation")
	}
	// Injected closure metadata checks projection lifetime only. It is not a
	// signed native/Gone validation or proof of actual listener shutdown.
	g.Lifecycle.Proof = make([]byte, 64)
	released := put(s, key, g)
	if _, err = project(released, smaller, own); err == nil {
		t.Fatal("signed-Gone boundary erased pending target ingress budget")
	}
	if _, err = project(released, tight, own); err != nil {
		t.Fatal("pending target did not take over released original slot", err)
	}
	taskKey := deployment.ResourceKey("task", "tenant", "first", "web")
	_ = json.Unmarshal([]byte(s.Object(taskKey).Value), &g)
	g.Lifecycle = &schema.Lifecycle{Drain: true, Nonce: [16]byte{2}}
	if _, err = project(put(s, taskKey, g), q); err == nil {
		t.Fatal("backend drained before original Ingress release")
	}
}
