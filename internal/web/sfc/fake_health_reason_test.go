// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"testing"

	"github.com/jay94ks/seafield/internal/deployment"
)

// A degraded app carries sfcd's first cause so the screen can show one line
// beside the badge ("worker exit code 137 · node-b").
func TestFakeAppHealthReason(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	alice := passwordLogin(t, f, "alice", "alice")
	apps, err := alice.Apps(ctx, "shop", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range apps.Items {
		switch a.App {
		case "shop-worker":
			r := a.HealthReason
			if r == nil || r.Code != deployment.HealthTaskExited || r.Exit == nil || *r.Exit != 137 || r.Name != "worker" || r.Node == "" {
				t.Fatalf("degraded reason %+v", r)
			}
		case "php-shop":
			if a.HealthReason != nil {
				t.Fatalf("healthy app has a reason %+v", a.HealthReason)
			}
		}
	}
}
