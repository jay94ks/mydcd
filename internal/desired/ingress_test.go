// SPDX-License-Identifier: Apache-2.0

package desired

import (
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/ingress"
	"github.com/jay94ks/mydcd/internal/schema"
	"testing"
)

func TestIngressCommittedReferencesAndPortBudgets(t *testing.T) {
	f := newFixture(t)
	f.apply(TaskPrefix+"a", f.task, state.Applied)
	n := NodeSpec{Schema: 1, Owner: f.owner, CPU: 1000000000, Memory: 128 << 20, MaxBridges: 2, MaxContainers: 4, MaxEndpoints: 4, MaxConsumers: 8, MaxIngressInstances: 2, MaxIngressListeners: 3, MaxIngressRequests: 4, MaxIngressConnections: 8, IngressBufferBytes: 256 << 10}
	f.apply(NodePrefix+"a", n, state.Applied)
	s := ingress.Spec{Schema: 1, Owner: f.owner, Listeners: []ingress.Listener{{ID: "http", Address: "0.0.0.0:18080"}}, Routes: []ingress.Route{{ID: "r", Host: "*", Prefix: "/", Service: "api"}}, Services: []ingress.Service{{ID: "api", Backends: []ingress.BackendSpec{{ID: "a", Task: TaskPrefix + "a", Network: f.bridge.Network, Generation: f.s.Object(TaskPrefix + "a").Generation, Address: f.task.IPv4, Port: 8080, Weight: 1, Capacity: 2, HealthPath: "/health"}}}}, MaxRequests: 2, MaxConnections: 4, MaxHeaderBytes: 4096, BufferBytes: 128 << 10, MaxBodyBytes: 1024, RequestTimeoutMS: 5000, DialTimeoutMS: 100, ResponseHeaderTimeoutMS: 100, HealthIntervalMS: 100}
	f.apply(IngressPrefix+"a", s, state.Applied)
	limited := n
	limited.MaxConsumers = 1
	f.apply(NodePrefix+"a", limited, state.Invalid)
	f.apply(IngressPrefix+"conflict", s, state.Invalid)
	drain := f.task
	drain.Lifecycle = schema.Lifecycle{Drain: true, Nonce: [16]byte{2}}
	f.apply(TaskPrefix+"a", drain, state.Invalid)
	s.Lifecycle = schema.Lifecycle{Drain: true, Nonce: [16]byte{3}}
	f.apply(IngressPrefix+"a", s, state.Applied)
	f.apply(TaskPrefix+"a", drain, state.Invalid)
	s.Lifecycle.Proof = f.proof(IngressPrefix+"a", s)
	f.apply(IngressPrefix+"a", s, state.Applied)
	f.apply(TaskPrefix+"a", drain, state.Applied)
	f.apply(IngressPrefix+"a", nil, state.Applied)
}
