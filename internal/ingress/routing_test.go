// SPDX-License-Identifier: Apache-2.0

package ingress

import (
	"encoding/json"
	"testing"
)

func TestHostPathPrecedenceAndAmbiguity(t *testing.T) {
	table, err := NewTable([]Route{{ID: "fallback", Host: "*", Prefix: "/", Service: "default"}, {ID: "wild", Host: "*.example.com", Prefix: "/api", Service: "wild"}, {ID: "exact", Host: "API.EXAMPLE.COM.", Prefix: "/", Service: "exact"}, {ID: "long", Host: "api.example.com", Prefix: "/api/v1", Service: "v1"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ host, path, want string }{{"API.example.com.", "/api/v1/task", "long"}, {"api.example.com", "/api/v10", "exact"}, {"other.example.com", "/api/x", "wild"}, {"other.example.com", "/apix", "fallback"}, {"example.com", "/api", "fallback"}, {"example.com.evil", "/api", "fallback"}} {
		r, err := table.Match(c.host, c.path)
		if err != nil || r.ID != c.want {
			t.Fatal(c, r, err)
		}
	}
	for _, path := range []string{"", "api", "/../api", "/a/./b", "/a%2fb", "/a\\b", "//api", "/api?x"} {
		if _, err := table.Match("api.example.com", path); err == nil {
			t.Fatal("ambiguous path", path)
		}
	}
	for _, routes := range [][]Route{{{ID: "a", Host: "example.com", Prefix: "/", Service: "svc"}, {ID: "b", Host: "EXAMPLE.COM.", Prefix: "/", Service: "other"}}, {{ID: "a", Host: "bad:443", Prefix: "/", Service: "svc"}}, {{ID: "a", Host: "*example.com", Prefix: "/", Service: "svc"}}, {{ID: "a", Host: "example.com", Prefix: "/x/", Service: "svc"}}} {
		if _, err := NewTable(routes); err == nil {
			t.Fatal("invalid/ambiguous table")
		}
	}
}
func TestWeightedHealthSelectionAndUserPreservingDrain(t *testing.T) {
	b, _ := NewBalancer(10)
	a := Backend{ID: "a", Generation: 1, Weight: 1, Capacity: 4, Healthy: true, ObservedAt: 100}
	other := Backend{ID: "b", Generation: 1, Weight: 3, Capacity: 4, Healthy: true, ObservedAt: 100}
	if b.Update(a) != nil || b.Update(other) != nil {
		t.Fatal("backend init")
	}
	counts := map[string]int{}
	for i := 0; i < 8; i++ {
		l, err := b.Acquire(110)
		if err != nil {
			t.Fatal(err)
		}
		counts[l.Backend]++
		if b.Release(l) != nil {
			t.Fatal("release")
		}
	}
	if counts["a"] != 2 || counts["b"] != 6 {
		t.Fatal("weights", counts)
	}
	if _, err := b.Acquire(111); err == nil {
		t.Fatal("stale health used")
	}
	l, err := b.Acquire(100)
	if err != nil {
		t.Fatal(err)
	}
	a.Draining = true
	other.Draining = true
	if b.Update(a) != nil || b.Update(other) != nil {
		t.Fatal("drain")
	}
	if _, err := b.Acquire(100); err == nil {
		t.Fatal("new user admitted while draining")
	}
	if b.Remove(l.Backend, 1) == nil {
		t.Fatal("deleted in-use backend")
	}
	data, _ := json.Marshal(b.Checkpoint())
	var j BalanceJournal
	_ = json.Unmarshal(data, &j)
	b, err = RestoreBalancer(j)
	if err != nil {
		t.Fatal(err)
	}
	if b.Remove(l.Backend, 1) == nil || b.Release(l) != nil || b.Release(l) == nil {
		t.Fatal("restart lost pin or allowed double release")
	}
	if b.Remove(l.Backend, 1) != nil {
		t.Fatal("last user did not permit retirement")
	}
	a.ID = l.Backend
	a.Draining = false
	if b.Update(a) == nil {
		t.Fatal("generation reused after retirement")
	}
	a.Generation = 2
	if b.Update(a) != nil {
		t.Fatal("new generation")
	}
	fresh, err := b.Acquire(100)
	if err != nil {
		t.Fatal(err)
	}
	if b.Release(l) == nil || b.Release(fresh) != nil {
		t.Fatal("stale lease freed replacement")
	}
}
func TestBackendHealthCapacityAndStaleUpdates(t *testing.T) {
	b, _ := NewBalancer(5)
	s := Backend{ID: "one", Generation: 1, Weight: 1, Capacity: 1, Healthy: false, ObservedAt: 10}
	if b.Update(s) != nil {
		t.Fatal("init")
	}
	if _, err := b.Acquire(10); err == nil {
		t.Fatal("unhealthy backend")
	}
	s.Healthy = true
	if b.Update(s) != nil {
		t.Fatal("healthy update")
	}
	l, err := b.Acquire(10)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Acquire(10); err == nil {
		t.Fatal("capacity exceeded")
	}
	bad := s
	bad.ObservedAt = 9
	if b.Update(bad) == nil {
		t.Fatal("old observation")
	}
	bad = s
	bad.Generation = 2
	if b.Update(bad) == nil {
		t.Fatal("generation replaced live users")
	}
	s.Healthy = false
	if b.Update(s) != nil || b.Release(l) != nil {
		t.Fatal("health failure interrupted existing release")
	}
}
