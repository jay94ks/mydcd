// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/schema"
)

func TestFrozenGoalProjectsTypedBridgeAndOriginalResourceSources(t *testing.T) {
	f := makeFixture(t)
	b, err := Compile(smallCompose(t), f.c, contextFor(t, f))
	if err != nil {
		t.Fatal(err)
	}
	poolIDs := map[string]bool{}
	for _, step := range b.Steps() {
		if step.Kind != "bridge" && step.Kind != "task" {
			continue
		}
		g := GoalCommand{Schema: 1, Cluster: f.cluster, Tenant: "tenant", App: "php-mysql", Deployment: "deploy", Kind: step.Kind, Node: step.Node, Owner: step.Owner, Config: step.Goal}
		raw, _ := json.Marshal(g)
		o := state.Object{Present: true, Generation: 50, Revision: 55, Value: string(raw)}
		projected, err := DecodeGoalResources(f.cluster, step.Key, o)
		if err != nil {
			t.Fatal(step.Kind, err)
		}
		if step.Kind == "bridge" {
			if projected.Bridge == nil || projected.Network == nil || projected.Network.Generation != 50 || projected.Network.Revision != 55 || projected.Bridge.Owner != engine.Owner(f.cluster, step.Owner) || projected.Bridge.Network != projected.Network.ID || projected.Bridge.MTU != 1280 || !projected.Bridge.Internal {
				t.Fatal("typed bridge/original source")
			}
			poolID := projected.Bridge.Pools[0].ID
			if poolID != projected.Network.ID+"/pool" || poolIDs[poolID] {
				t.Fatal("native pool identity is not globally unique")
			}
			poolIDs[poolID] = true
			var declaration bridgeDeclaration
			_ = json.Unmarshal(g.Config, &declaration)
			declaration.Pool.AddressPlan = &AddressPlan{DockerRange: "10.0.0.0/25"}
			altered := g
			altered.Config, _ = json.Marshal(declaration)
			alteredRaw, _ := json.Marshal(altered)
			badSource := o
			badSource.Value = string(alteredRaw)
			if _, err = DecodeGoalResources(f.cluster, step.Key, badSource); err == nil {
				t.Fatal("unconnected Docker range silently dropped")
			}

		} else if projected.Reservation == nil || projected.Reservation.Generation != 50 || projected.Reservation.Revision != 55 || projected.Reservation.Key != step.Key || projected.Reservation.Need.CPU == 0 || projected.Reservation.Need.Memory == 0 {
			t.Fatal("task budget source")
		}
		g.Lifecycle = &schema.Lifecycle{Drain: true, Nonce: [16]byte{1}}
		raw, _ = json.Marshal(g)
		o.Value = string(raw)
		draining, err := DecodeGoalResources(f.cluster, step.Key, o)
		if err != nil || draining.Network != nil && !draining.Network.Draining || draining.Reservation != nil && !draining.Reservation.Draining {
			t.Fatal("Drain returned space", err)
		}
		if _, err = DecodeGoalResources([32]byte{99}, step.Key, o); err == nil {
			t.Fatal("foreign cluster")
		}
		if _, err = DecodeGoalResources(f.cluster, step.Key+"/foreign", o); err == nil && step.Kind == "bridge" {
			t.Fatal("foreign key")
		}
	}
}

func TestComposeUsesCommittedAddressSourcesBeforeProposal(t *testing.T) {
	f := makeFixture(t)
	c := smallCompose(t)
	ctx := contextFor(t, f)
	ctx.Addresses = map[string]ObjectRef{"10.240.10.10": {Key: ResourceKey("task", "tenant", "other", "web"), Generation: 1, Revision: 2}}
	if _, err := Compile(c, f.c, ctx); err == nil {
		t.Fatal("existing other app address ignored")
	}
}
