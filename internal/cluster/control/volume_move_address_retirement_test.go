// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/schema"
)

func TestMoveAddressHoldSurvivesOriginalTaskTombstoneWithoutReleasingDNS(t *testing.T) {
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	owner := [32]byte(private.Public().(ed25519.PublicKey))
	scope := deployment.AppScope{Cluster: [32]byte{72}, Actor: "manager", Tenant: "tenant", App: "app", Deployment: "deploy"}
	key := deployment.ResourceKey("task", scope.Tenant, scope.App, "web")
	ip := netip.MustParseAddr("10.90.0.10")
	encode := func(v any) []byte {
		t.Helper()
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	service := deployment.ComposeService{Networks: map[string]deployment.Attachment{"lan": {IPv4: ip.String()}}}
	goal := deployment.GoalCommand{Schema: 1, Cluster: scope.Cluster, Tenant: scope.Tenant, App: scope.App, Deployment: scope.Deployment, Kind: "task", Node: "node-a", Owner: owner, Config: encode(service)}
	s, err := state.New("admin")
	if err != nil {
		t.Fatal(err)
	}
	apply := func(c state.Command) state.Result {
		t.Helper()
		var result state.Result
		s, result, err = state.Apply(s, s.Index()+1, c)
		if err != nil || result.Code != state.Applied {
			t.Fatal("pure original Goal/tombstone fixture", result, err)
		}
		return result
	}
	original := state.Command{Actor: "admin", Epoch: 1, RequestID: "retirement-1", Key: key, Value: string(encode(goal))}
	created := apply(original)
	live := s
	goal.Lifecycle = &schema.Lifecycle{Drain: true, Nonce: [16]byte{2}}
	drain := state.Command{Actor: "admin", Epoch: 1, RequestID: "retirement-2", Key: key, Expected: created.Revision, Value: string(encode(goal))}
	drained := apply(drain)
	signature := ed25519.Sign(private, schema.GoneBytes(scope.Cluster, key, created.Generation, []byte(drain.Value)))
	goal.Lifecycle.Proof = signature
	proof := state.Command{Actor: "admin", Epoch: 1, RequestID: "retirement-3", Key: key, Expected: drained.Revision, Value: string(encode(goal))}
	proved := apply(proof)
	apply(state.Command{Actor: "admin", Epoch: 1, RequestID: "retirement-4", Key: key, Expected: proved.Revision, Delete: true})
	book, _ := network.NewBook(4)
	book, err = book.AddPool(network.Pool{ID: "pool", Network: "tenant/shared", Owner: hex.EncodeToString(owner[:]), Prefix: netip.MustParsePrefix("10.90.0.0/24"), Gateway: netip.MustParseAddr("10.90.0.1"), MTU: 1280})
	if err != nil {
		t.Fatal(err)
	}
	book, held, err := book.Reserve(key+"/lan/0", hex.EncodeToString(owner[:]), "tenant/shared", "pool", created.Generation, ip)
	if err != nil {
		t.Fatal(err)
	}
	demand := deployment.ResourceDemand{Key: key, Kind: "task", Node: "node-a", Owner: owner, Addresses: []deployment.StaticAddressDemand{{Endpoint: held.Endpoint, Network: "tenant/shared", Address: ip}}}
	out := ResourceProjection{Addresses: book, AddressSources: map[string]deployment.ObjectRef{ip.String(): {Key: held.Endpoint, Generation: held.Generation}}, Goals: map[string]deployment.GoalResources{}}
	target := deployment.RetirementTarget{Original: deployment.Claim{Step: deployment.Step{Key: key, Kind: "task", Node: demand.Node, Owner: owner}, Command: original, Result: created}, Drain: &deployment.Mutation{Command: drain, Result: &drained}, Proof: &deployment.Mutation{Command: proof, Result: &proved}, Gone: signature}
	retiring := &moveAddressRetirement{state: s, view: deployment.RetirementView{ID: "original-move", Down: true, Targets: []deployment.RetirementTarget{target}}}
	if admitMoveAddresses(out, scope, demand, nil) == nil {
		t.Fatal("unqualified orphan became a future reservation")
	}
	if err := admitMoveAddresses(out, scope, demand, retiring); err != nil {
		t.Fatal("same accepted retirement lost its future slot at Goal deletion", err)
	}
	if current, ok := out.Addresses.AllocationAt(ip); !ok || current != held {
		t.Fatal("future reservation returned/changed the original DNS hold", current)
	}
	if _, _, err := out.Addresses.Reserve(held.Endpoint, held.Owner, "tenant/shared", held.Pool, held.Generation+1, ip); err == nil {
		t.Fatal("reservation was confused with permission to activate a new generation")
	}
	for name, change := range map[string]func(*moveAddressRetirement){
		"no native proof":     func(r *moveAddressRetirement) { r.view.Targets[0].Proof = nil },
		"forged Gone":         func(r *moveAddressRetirement) { r.view.Targets[0].Gone[0] ^= 1 },
		"other generation":    func(r *moveAddressRetirement) { r.view.Targets[0].Original.Result.Generation++ },
		"other frozen owner":  func(r *moveAddressRetirement) { r.view.Targets[0].Original.Step.Owner[0] ^= 1 },
		"other frozen task":   func(r *moveAddressRetirement) { r.view.Targets[0].Original.Step.Key += "-other" },
		"live replacement":    func(r *moveAddressRetirement) { r.state = live },
		"other frozen config": func(r *moveAddressRetirement) { r.view.Targets[0].Original.Command.Value = "{}" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := &moveAddressRetirement{state: s}
			if err := json.Unmarshal(encode(retiring.view), &bad.view); err != nil {
				t.Fatal(err)
			}
			change(bad)
			if admitMoveAddresses(out, scope, demand, bad) == nil {
				t.Fatal("unrelated/unsigned retirement retained another allocation")
			}
		})
	}
	for name, change := range map[string]func(*deployment.ResourceDemand){
		"other node":     func(d *deployment.ResourceDemand) { d.Node = "node-b" },
		"other owner":    func(d *deployment.ResourceDemand) { d.Owner[0] ^= 1 },
		"other endpoint": func(d *deployment.ResourceDemand) { d.Addresses[0].Endpoint += "-other" },
		"other network":  func(d *deployment.ResourceDemand) { d.Addresses[0].Network = "tenant/other" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := demand
			bad.Addresses = append([]deployment.StaticAddressDemand(nil), demand.Addresses...)
			change(&bad)
			if admitMoveAddresses(out, scope, bad, retiring) == nil {
				t.Fatal("future demand borrowed another identity")
			}
		})
	}
	other := scope
	other.Deployment = "other"
	if admitMoveAddresses(out, other, demand, retiring) == nil {
		t.Fatal("other deployment borrowed the retired Goal")
	}
	out.MoveHolds = []deployment.PlannedResource{{Origin: [32]byte{3}, Scope: scope, Demand: demand}}
	if admitMoveAddresses(out, scope, demand, retiring) == nil {
		t.Fatal("another pending intent borrowed the same future slot")
	}
}
