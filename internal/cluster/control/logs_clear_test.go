// SPDX-License-Identifier: Apache-2.0

package control

import (
	"testing"

	"github.com/jay94ks/seafield/internal/containerops"
)

func TestLogsClearValid(t *testing.T) {
	for _, c := range []struct {
		q  LogsClear
		ok bool
	}{
		{LogsClear{Tenant: "t", Selection: containerops.Selection{App: "web"}}, true},
		{LogsClear{Tenant: "t", Selection: containerops.Selection{App: "web", Service: "api"}}, true},
		{LogsClear{Tenant: "t", Selection: containerops.Selection{Standalone: "s1"}}, true},
		{LogsClear{Tenant: "t", Selection: containerops.Selection{App: "web", Service: "api", Instance: "workload/task/t/web/api/n1/r2"}}, true},
		{LogsClear{Selection: containerops.Selection{App: "web"}}, false},
		{LogsClear{Tenant: "t", Selection: containerops.Selection{App: "web", Standalone: "s1"}}, false},
		{LogsClear{Tenant: "t", Selection: containerops.Selection{App: "web", Instance: "network/tun/x"}}, false},
	} {
		if c.q.Valid() != c.ok {
			t.Errorf("%+v: Valid() = %v", c.q, !c.ok)
		}
	}
}

func TestLogsClearMatch(t *testing.T) {
	m := LogsClearMatch{Tenant: "t", Scope: "web", Service: "api"}
	if !m.Matches("t", "web", "api", "workload/task/t/web/api") || m.Matches("t", "web", "db", "workload/task/t/web/db") || m.Matches("u", "web", "api", "") {
		t.Fatal("service match")
	}
	all := LogsClearMatch{Tenant: "t", Scope: "web"}
	if !all.Matches("t", "web", "db", "x") {
		t.Fatal("whole app")
	}
	one := LogsClearMatch{Tenant: "t", Scope: "web", Instance: "workload/task/t/web/api/n1/r1"}
	if one.Matches("t", "web", "api", "workload/task/t/web/api/n1/r2") {
		t.Fatal("instance")
	}
}
