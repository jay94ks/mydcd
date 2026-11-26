// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/control"
)

// A fixed published port on a server already held by another task is
// HOST_PORT_CONFLICT at plan time; dynamic ports, other servers, other
// protocols and other addresses do not conflict.
func TestHostPortConflict(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	alice := passwordLogin(t, f, "alice", "alice")
	def := control.StandaloneDefinition{Name: "pub", Lifetime: "fixed"}
	doc := []byte("services:\n  pub:\n    image: busybox:1.36\n    networks: [shop-net]\n    ports:\n      - \"127.0.0.1:18080:8080/tcp\"\n      - {target: 53, published: \"15353\", protocol: udp}\n    x-mydc: {node: node-a}\n")
	p, err := alice.AppPlan(ctx, AppPlanRequest{Tenant: "shop", Document: doc, Standalone: &def})
	if err != nil {
		t.Fatal(err)
	}
	target := control.AppCreateTarget(clusterOf(t, alice), "shop", p.App, "dep-"+p.App)
	uploadApp(t, alice, "shop", p.App, "up-pub", p.Data)
	b := control.AppBegin{Standalone: &def, Target: &target, Tenant: "shop", App: p.App, Deployment: "dep-" + p.App, Upload: "up-pub", Operation: "up-pub"}
	if _, res := submit(t, alice, ActionStandaloneUp, 0, b, rootFor(t, alice, ActionStandaloneUp)); res.Code != ResultApplied {
		t.Fatalf("up %+v", res)
	}
	// Re-planning the same owner is not a conflict.
	if _, err := alice.AppPlan(ctx, AppPlanRequest{Tenant: "shop", Document: doc, Standalone: &def}); err != nil {
		t.Fatalf("same owner %v", err)
	}
	app := func(ports string, node string) error {
		d := "name: port-app\nservices:\n  web:\n    image: nginx:1.27\n    ports: " + ports + "\n    x-mydc: {node: " + node + "}\n"
		_, err := alice.AppPlan(ctx, AppPlanRequest{Tenant: "shop", Document: []byte(d)})
		return err
	}
	for _, c := range []struct {
		ports, node string
		conflict    bool
	}{
		{`["18080:80"]`, "node-a", true}, // wildcard address overlaps 127.0.0.1
		{`["127.0.0.1:18080:80"]`, "node-a", true},
		{`["10.0.0.11:18080:80"]`, "node-a", false}, // another address
		{`["18080:80"]`, "node-b", false},           // another server
		{`["18080:80/udp"]`, "node-a", false},       // another protocol
		{`[{target: 5353, published: 15353, protocol: udp}]`, "node-a", true},
		{`["80", "0:80", "20000-20010:80"]`, "node-a", false}, // dynamic
	} {
		err := app(c.ports, c.node)
		e, _ := err.(*Error)
		if got := e != nil && e.InputCode == InputHostPortConflict; got != c.conflict || !c.conflict && err != nil {
			t.Fatalf("%s on %s: %v", c.ports, c.node, err)
		}
	}
	// Two services of one app on one server.
	d := "name: twin\nservices:\n  a:\n    image: nginx:1.27\n    ports: [\"9000:80\"]\n    x-mydc: {node: node-b}\n  b:\n    image: nginx:1.27\n    ports: [\"9000:80\"]\n    x-mydc: {node: node-b}\n"
	if _, err := alice.AppPlan(ctx, AppPlanRequest{Tenant: "shop", Document: []byte(d)}); err == nil || err.(*Error).InputCode != InputHostPortConflict {
		t.Fatalf("twin %v", err)
	}
	// Another standalone on the same port.
	def2 := control.StandaloneDefinition{Name: "pub2", Lifetime: "fixed"}
	doc2 := []byte("services:\n  pub2:\n    image: busybox:1.36\n    networks: [shop-net]\n    ports: [\"18080:8080\"]\n    x-mydc: {node: node-a}\n")
	if _, err := alice.AppPlan(ctx, AppPlanRequest{Tenant: "shop", Document: doc2, Standalone: &def2}); err == nil || err.(*Error).InputCode != InputHostPortConflict {
		t.Fatalf("standalone %v", err)
	}
}

func TestParseComposePortIPv6(t *testing.T) {
	p, ok := parseComposePort("[::1]:8080:80/udp")
	if n, fixed := p.fixed(); !ok || p.IP != "::1" || p.Target != 80 || p.Proto != "udp" || !fixed || n != 8080 {
		t.Fatalf("%+v %v", p, ok)
	}
}
