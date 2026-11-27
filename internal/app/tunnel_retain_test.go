// SPDX-License-Identifier: Apache-2.0

package app

import (
	"testing"

	"github.com/jay94ks/seafield/internal/network"
)

func TestRetainedPlanRevokesOnlyTheMembersThatLeftOrRekeyed(t *testing.T) {
	stay, left, rekeyed := [32]byte{1}, [32]byte{2}, [32]byte{3}
	plan := network.PacketPlan{Peers: map[[32]byte]network.PacketPeer{
		stay: {WireKey: [32]byte{11}}, left: {WireKey: [32]byte{12}}, rekeyed: {WireKey: [32]byte{13}},
	}}
	owners := map[string][32]byte{"stay": stay, "rekeyed": rekeyed, "joined": {4}}
	wires := map[string][32]byte{"stay": {11}, "rekeyed": {99}, "joined": {14}}
	got := retainedPlan(plan, owners, wires)
	if len(got.Peers) != 1 || got.Peers[stay].WireKey != ([32]byte{11}) {
		t.Fatalf("retained %v", got.Peers)
	}
	if len(plan.Peers) != 3 {
		t.Fatal("the serving plan was changed in place")
	}
}
