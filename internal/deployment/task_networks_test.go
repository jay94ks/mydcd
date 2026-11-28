// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/network"
)

// db joins a second node-local network "back" next to its overlay "app".
func twoNetworkTask(t *testing.T) (Blueprint, TaskMaterial) {
	t.Helper()
	_, b, material := taskMaterialFixtureWith(t, func(c *Compose) {
		c.Networks["back"] = ComposeNetwork{Sfc: NetworkExtension{MTU: 1280, Pools: map[string]PoolDeclaration{"node-b": {CIDR: "10.241.20.0/24", Gateway: "10.241.20.1"}}}}
		s := c.Services["db"]
		s.Networks = map[string]Attachment{"app": s.Networks["app"], "back": {IPv4: "10.241.20.10"}}
		c.Services["db"] = s
	})
	netID := PoolID("tenant", "php-mysql", "back", "node-b")
	owner := material.Bridge.Owner
	bridge := network.BridgeSpec{Schema: 1, Network: netID, Owner: owner, MTU: 1280, Internal: true, Pools: []network.Pool{{ID: "pool", Network: netID, Owner: owner, Prefix: netip.MustParsePrefix("10.241.20.0/24"), Gateway: netip.MustParseAddr("10.241.20.1"), MTU: 1280}}}
	material.Extra = []TaskNetworkBinding{{Alias: "back", Network: ObjectRef{ResourceKey("bridge", "tenant", "php-mysql", "back/node-b"), 11, 11}, Bridge: bridge}}
	return b, material
}

func TestTaskRecipeBindsEveryNetworkInAliasOrder(t *testing.T) {
	b, material := twoNetworkTask(t)
	_, spec, err := b.taskRecipe("db", material, material.Bridge.Owner)
	if err != nil {
		t.Fatal(err)
	}
	if spec.Bridge != material.Network.Key || spec.IPv4 != netip.MustParseAddr("10.240.20.10") || len(spec.Attachments) != 1 {
		t.Fatal("primary attachment is not the first alias", spec.Bridge, spec.IPv4, spec.Attachments)
	}
	back := spec.Attachments[0]
	if back.Bridge != material.Extra[0].Network.Key || back.BridgeGeneration != 11 || back.IPv4 != netip.MustParseAddr("10.241.20.10") || back.BridgeOwner != "" {
		t.Fatal("second network bound to the wrong source", back)
	}
	// The node-local network adds no overlay route; app's remote routes stay.
	if len(spec.Routes) != 2 || spec.Routes[0].Gateway != netip.MustParseAddr("10.240.20.1") {
		t.Fatal("routes changed by the second network", spec.Routes)
	}
	for name, mutate := range map[string]func(*TaskMaterial){
		"missing":     func(m *TaskMaterial) { m.Extra = nil },
		"wrong alias": func(m *TaskMaterial) { m.Extra[0].Alias = "front" },
		"wrong source": func(m *TaskMaterial) {
			m.Extra[0].Network.Key = ResourceKey("bridge", "tenant", "php-mysql", "app/node-b")
		},
		"draining":      func(m *TaskMaterial) { m.Extra[0].Bridge.Lifecycle.Drain = true },
		"other gateway": func(m *TaskMaterial) { m.Extra[0].Bridge.Pools[0].Gateway = netip.MustParseAddr("10.241.20.2") },
		"extra network": func(m *TaskMaterial) { m.Extra = append(m.Extra, m.Extra[0]) },
	} {
		bad := material
		bad.Extra = append([]TaskNetworkBinding(nil), material.Extra...)
		bad.Extra[0].Bridge.Pools = append([]network.Pool(nil), material.Extra[0].Bridge.Pools...)
		mutate(&bad)
		if _, _, err := b.taskRecipe("db", bad, material.Bridge.Owner); err == nil {
			t.Fatal("recipe accepted mismatched network material", name)
		}
	}
	short := material
	short.Extra = nil
	_, _, err = b.taskRecipe("db", short, material.Bridge.Owner)
	var input *InputError
	if !errors.As(err, &input) || !strings.Contains(err.Error(), "db.networks") {
		t.Fatal("missing network material not named", err)
	}
}
