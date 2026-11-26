// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"slices"
	"strconv"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/ingress"
	"github.com/jay94ks/mydcd/internal/network"
)

func (r IngressRuntime) spec() ingress.Spec {
	return ingress.Spec{MaxRequests: r.MaxRequests, MaxConnections: r.MaxConnections, MaxHeaderBytes: r.MaxHeaderBytes, MaxBodyBytes: r.MaxBodyBytes, BufferBytes: r.BufferBytes, RequestTimeoutMS: r.RequestTimeoutMS, DialTimeoutMS: r.DialTimeoutMS, ResponseHeaderTimeoutMS: r.ResponseHeaderTimeoutMS, HealthIntervalMS: r.HealthIntervalMS}
}
func (r IngressRuntime) validate() error { return ingress.ValidateLimits(r.spec()) }

func ingressNetwork(i IngressDeclaration, s ComposeService) (string, error) {
	if i.Backend.Network != "" {
		if _, ok := s.Networks[i.Backend.Network]; !ok {
			return "", ErrInputs
		}
		return i.Backend.Network, nil
	}
	if len(s.Networks) != 1 {
		return "", inputError("INGRESS_NETWORK_REQUIRED", i.Backend.Service)
	}
	for alias := range s.Networks {
		return alias, nil
	}
	return "", ErrInputs
}

// ResolveIngress binds the immutable original listener demand to the exact
// committed Task and native network sources. It performs no health/native IO.
func ResolveIngress(cluster [32]byte, key string, o state.Object, objects map[string]state.Object) (ingress.Spec, error) {
	g, err := DecodeGoalResources(cluster, key, o)
	if err != nil || g.Goal.Kind != "ingress" || key != ResourceKey("ingress", g.Goal.Tenant, g.Goal.App, "http") {
		return ingress.Spec{}, ErrInputs
	}
	goal := g.Goal
	var i IngressDeclaration
	if json.Unmarshal(goal.Config, &i) != nil || i.Node != goal.Node || i.Runtime.validate() != nil {
		return ingress.Spec{}, ErrInputs
	}
	refs := map[string]state.Object{}
	for _, ref := range goal.Dependencies {
		v, exists := objects[ref.Key]
		if !exists || !v.Present || v.Generation != ref.Generation || v.Revision != ref.Revision {
			return ingress.Spec{}, ErrInputs
		}
		if _, exists := refs[ref.Key]; exists {
			return ingress.Spec{}, ErrInputs
		}
		refs[ref.Key] = v
	}
	for _, taskKey := range goal.Follow {
		if _, duplicate := refs[taskKey]; duplicate {
			return ingress.Spec{}, ErrInputs
		}
		if current, present := objects[taskKey]; present && current.Present {
			refs[taskKey] = current
		}
	}
	// Only committed Task dependencies of the declared services become backends.
	// The exact union of their network dependencies is checked below; an extra
	// source cannot be smuggled into the listener's accepted binding.
	var taskKeys []string
	for key, object := range refs {
		dependency, err := DecodeGoalResources(cluster, key, object)
		if err != nil {
			return ingress.Spec{}, ErrInputs
		}
		if dependency.Goal.Kind == "task" {
			taskKeys = append(taskKeys, key)
		}
	}
	if len(taskKeys) == 0 && len(goal.Follow) == 0 || len(taskKeys) > 1024 {
		return ingress.Spec{}, ErrInputs
	}
	slices.Sort(taskKeys)
	expected := map[string]bool{}
	if len(goal.Follow) != 0 {
		// Every fixed network source remains a lifetime pin, including a
		// temporarily absent backend's source. Task identities follow only
		// their own currently committed generation within this exact app.
		for _, ref := range goal.Dependencies {
			dependency, err := DecodeGoalResources(cluster, ref.Key, refs[ref.Key])
			if err != nil {
				return ingress.Spec{}, ErrInputs
			}
			if dependency.Goal.Kind == "task" {
				// Singleton tasks remain exact fixed references when another
				// declared service follows replica generations. The route below
				// must consume this task before it enters the expected set.
				continue
			}
			if dependency.Goal.Kind != "bridge" && dependency.Goal.Kind != "tunnel" && dependency.Goal.Kind != "network-ref" {
				return ingress.Spec{}, ErrInputs
			}
			expected[ref.Key] = true
		}
	}
	s := i.Runtime.spec()
	s.Schema = 1
	s.DynamicBackends = len(goal.Follow) != 0
	if s.DynamicBackends {
		s.BindingRevision = o.Revision
		for _, object := range refs {
			s.BindingRevision = max(s.BindingRevision, object.Revision)
		}
	}
	s.Owner = engine.Owner(cluster, goal.Owner)
	s.Tenant, s.App = goal.Tenant, goal.App
	for n, l := range i.Listeners {
		s.Listeners = append(s.Listeners, ingress.Listener{ID: "listener-" + strconv.Itoa(n+1), Address: l.Address, TLS: l.TLS, HTTP3: l.HTTP3, Shared: l.Shared})
	}
	for _, route := range IngressRoutes(i) {
		declaration := ingressForRoute(i, route)
		serviceID := route.Service
		if len(i.Routes) > 0 {
			serviceID = route.ID
		}
		var backends []ingress.BackendSpec
		for _, taskKey := range taskKeys {
			resource, e := DecodeGoalResources(cluster, taskKey, refs[taskKey])
			if e != nil {
				return ingress.Spec{}, e
			}
			var task ComposeService
			if json.Unmarshal(resource.Goal.Config, &task) != nil {
				return ingress.Spec{}, ErrInputs
			}
			instance, e := TaskInstanceForKey(goal.Tenant, goal.App, taskKey, task)
			if e != nil {
				return ingress.Spec{}, e
			}
			if instance.Service != route.Service {
				continue
			}
			backend, e := resolveIngressBackend(cluster, goal, declaration, taskKey, refs, objects, expected)
			if e != nil {
				return ingress.Spec{}, e
			}
			if s.DynamicBackends {
				// A mixed fixed/followed snapshot carries each actual source
				// revision. Fixed tasks still passed their exact dependency
				// check above and never enter the Follow set.
				backend.Revision = refs[taskKey].Revision
			}
			if len(i.Routes) > 0 {
				backend.ID = route.ID + "/" + backend.ID
			}
			backends = append(backends, backend)
		}
		s.Services = append(s.Services, ingress.Service{ID: serviceID, Backends: backends})
		s.Routes = append(s.Routes, ingress.Route{ID: route.ID, Host: route.Host, Prefix: route.Prefix, Service: serviceID, Gateway: route.Gateway, Balance: route.Balance})
	}
	if len(expected) != len(refs) {
		return ingress.Spec{}, ErrInputs
	}
	if goal.Lifecycle != nil {
		s.Lifecycle = *goal.Lifecycle
		s.Lifecycle.Proof = append([]byte(nil), goal.Lifecycle.Proof...)
	}
	raw, _ := json.Marshal(s)
	return ingress.DecodeSpec(string(raw))
}

func resolveIngressBackend(cluster [32]byte, goal GoalCommand, i IngressDeclaration, taskKey string, refs, objects map[string]state.Object, expected map[string]bool) (ingress.BackendSpec, error) {
	task, err := DecodeGoalResources(cluster, taskKey, refs[taskKey])
	following := slices.Contains(goal.Follow, taskKey)
	if err != nil || task.Goal.Kind != "task" || task.Goal.Tenant != goal.Tenant || task.Goal.App != goal.App || task.Goal.Deployment != goal.Deployment || !following && task.Goal.Lifecycle != nil && task.Goal.Lifecycle.Drain {
		return ingress.BackendSpec{}, ErrInputs
	}
	var service ComposeService
	if json.Unmarshal(task.Goal.Config, &service) != nil || service.MyDC.Node != task.Goal.Node {
		return ingress.BackendSpec{}, ErrInputs
	}
	instance, err := TaskInstanceForKey(goal.Tenant, goal.App, taskKey, service)
	if err != nil || instance.Service != i.Backend.Service || following && instance.Ordinal == 0 {
		return ingress.BackendSpec{}, ErrInputs
	}
	expected[taskKey] = true
	alias, err := ingressNetwork(i, service)
	if err != nil {
		return ingress.BackendSpec{}, err
	}
	address := service.Networks[alias].IPv4
	if address == "" {
		address = service.Networks[alias].IPv6
	}
	ip, err := netip.ParseAddr(address)
	if err != nil {
		return ingress.BackendSpec{}, err
	}
	material, err := ResolveTaskNetwork(cluster, task.Goal, alias, objects)
	if err != nil {
		return ingress.BackendSpec{}, err
	}
	native, borrowed := material.Bridge, material.Reference
	contained := false
	for _, pool := range native.Pools {
		contained = contained || pool.Prefix.Contains(ip) && ip != pool.Gateway
	}
	if !contained {
		return ingress.BackendSpec{}, ErrInputs
	}
	name := goal.Tenant + "/" + goal.App + "/" + alias
	if borrowed != nil {
		name = borrowed.Namespace()
		localKey := ResourceKey("network-ref", goal.Tenant, goal.App, alias+"/"+goal.Node)
		expected[localKey] = true
		localGoal, err := DecodeGoalResources(cluster, localKey, refs[localKey])
		var local NetworkReference
		if err != nil || localGoal.Goal.Kind != "network-ref" || !sameNodeGoalOwner(cluster, goal, localGoal.Goal) || localGoal.Goal.Lifecycle != nil && localGoal.Goal.Lifecycle.Drain || json.Unmarshal(localGoal.Goal.Config, &local) != nil || local.Tenant != goal.Tenant || local.Node != goal.Node || local.Owner != localGoal.Goal.Owner || local.ManagedName != borrowed.ManagedName || local.PacketNetwork != borrowed.PacketNetwork {
			return ingress.BackendSpec{}, ErrInputs
		}
		if _, err = ReferenceBridge(cluster, local, objects); err != nil {
			return ingress.BackendSpec{}, err
		}
		if task.Goal.Node == goal.Node {
			if local.Source != borrowed.Source || !sameNodeGoalOwner(cluster, goal, task.Goal) {
				return ingress.BackendSpec{}, ErrInputs
			}
		} else {
			if borrowed.PacketNetwork == "" || len(local.Routes) == 0 || len(borrowed.Routes) == 0 {
				return ingress.BackendSpec{}, ErrInputs
			}
			for _, ref := range []NetworkReference{local, *borrowed} {
				tun, frozen := ref.LocalTunnel()
				tunKey := tun.Key
				t, err := network.DecodeTunnel(objects[tunKey].Value)
				if !frozen || err != nil || t.Network != name || t.Owner != engine.Owner(cluster, ref.Owner) || t.Lifecycle.Drain {
					return ingress.BackendSpec{}, ErrInputs
				}
			}
		}
	} else if task.Goal.Node != goal.Node {
		for _, node := range []string{goal.Node, task.Goal.Node} {
			tk := ResourceKey("tunnel", goal.Tenant, goal.App, alias+"/"+node)
			expected[tk] = true
			t, err := ResolveTunnel(cluster, tk, refs[tk], objects)
			if err != nil || t.Network != name || t.Lifecycle.Drain {
				return ingress.BackendSpec{}, ErrInputs
			}
			wantOwner := task.Goal.Owner
			if node == goal.Node {
				wantOwner = goal.Owner
			}
			if t.Owner != engine.Owner(cluster, wantOwner) {
				return ingress.BackendSpec{}, ErrInputs
			}
		}
	} else if !sameNodeGoalOwner(cluster, goal, task.Goal) {
		return ingress.BackendSpec{}, ErrInputs
	}
	id := i.Backend.Service
	if instance.Ordinal != 0 {
		digest := sha256.Sum256([]byte(taskKey))
		id = "task-" + hex.EncodeToString(digest[:])
	}
	backend := ingress.BackendSpec{ID: id, Task: taskKey, Generation: refs[taskKey].Generation, Network: name, Address: ip, Port: i.Backend.Port, Weight: 1, Capacity: i.Runtime.MaxRequests, HealthPath: i.Backend.HealthPath, Node: task.Goal.Node, Labels: service.Labels, Version: service.Labels["version"]}
	if following {
		backend.Revision = refs[taskKey].Revision
		backend.Draining = task.Goal.Lifecycle != nil && task.Goal.Lifecycle.Drain
	}
	return backend, nil
}
