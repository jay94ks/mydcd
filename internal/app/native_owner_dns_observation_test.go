// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/cluster/membership"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/network/services"
)

// Reuses the existing two signed identity transitions. DNS row/provenance and
// source versions below are modeled committed metadata; no socket, native
// Inspect, Ready, effect or live quorum success is claimed by this selector.
func managedDNSObservationFixture(t *testing.T) (lifecycle.Root, membership.Directory, string, state.Object, []managedDNSObservationCandidate) {
	t.Helper()
	root, members := installationIdentityFixture(t)
	key := services.ManagedDNSKey("tenant", "services")
	object := state.Object{Present: true, Generation: 7, Revision: 11}
	row := control.AppDNSOwner{Managed: &control.ManagedDNSOwnerSource{Node: "node-c"}, Source: deployment.ObjectRef{Key: key, Generation: object.Generation, Revision: object.Revision}, Config: services.DNSConfig{Tenant: "tenant", ID: "dns-one", Pool: "one"}, Reference: [32]byte{12}}
	return root, members, key, object, []managedDNSObservationCandidate{{owner: root.OriginalKey(), row: row}}
}

func TestManagedDNSObservationSelectsExactOriginalOwnerAcrossTwoRotationsAndPools(t *testing.T) {
	root, members, key, object, rows := managedDNSObservationFixture(t)
	second := rows[0]
	second.row.Config.ID, second.row.Config.Pool, second.row.Reference = "dns-two", "two", [32]byte{13}
	rows = append(rows, second)
	before, _ := json.Marshal(rows)
	for count := 0; count <= 2; count++ {
		directory := members
		directory.Entries = []membership.Entry{members.Entries[0]}
		directory.Entries[0].Keys = lifecycle.OwnIdentityTransitions(members.Entries[0].Keys[:count])
		current, err := identity.ParseKey(directory.Entries[0].CurrentPeer().Key)
		if err != nil {
			t.Fatal(err)
		}
		owner, err := managedDNSObservationIdentity(key, object, directory, current, rows)
		if err != nil || owner != root.OriginalKey() {
			t.Fatal("current membership lost exact original multi-pool DNS owner", count, err)
		}
		old := &Runtime{Identity: &identity.Identity{Public: owner}}
		r := &Runtime{Identity: &identity.Identity{Public: current}}
		if owner != current {
			r.nativeOwners = []*Runtime{old}
		}
		selected, found := r.nativeOwner(owner)
		if !found || selected.Identity.Public != owner || owner != current && selected != old {
			t.Fatal("original DNS namespace replaced by current runtime", count)
		}
		if count != 0 {
			if _, err := managedDNSObservationIdentity(key, object, directory, root.OriginalKey(), rows); err == nil {
				t.Fatal("historical key authenticated an observation")
			}
		}
	}
	after, _ := json.Marshal(rows)
	if !bytes.Equal(before, after) {
		t.Fatal("read-only selection changed original DNS source/ref/pools")
	}
}

func TestManagedDNSObservationRejectsMissingForeignChangedAndAmbiguousSources(t *testing.T) {
	root, members, key, object, rows := managedDNSObservationFixture(t)
	for _, tc := range []struct {
		name   string
		change func(*state.Object, *[]managedDNSObservationCandidate)
	}{
		{"missing-object", func(o *state.Object, _ *[]managedDNSObservationCandidate) { o.Present = false }},
		{"changed-generation", func(o *state.Object, _ *[]managedDNSObservationCandidate) { o.Generation++ }},
		{"changed-revision", func(o *state.Object, _ *[]managedDNSObservationCandidate) { o.Revision++ }},
		{"missing-row", func(_ *state.Object, r *[]managedDNSObservationCandidate) { *r = nil }},
		{"foreign-owner", func(_ *state.Object, r *[]managedDNSObservationCandidate) { (*r)[0].owner = [32]byte{99} }},
		{"foreign-node", func(_ *state.Object, r *[]managedDNSObservationCandidate) {
			m := *(*r)[0].row.Managed
			m.Node = "foreign"
			(*r)[0].row.Managed = &m
		}},
		{"missing-managed-provenance", func(_ *state.Object, r *[]managedDNSObservationCandidate) { (*r)[0].row.Managed = nil }},
		{"foreign-source-key", func(_ *state.Object, r *[]managedDNSObservationCandidate) {
			(*r)[0].row.Source.Key = services.ManagedDNSKey("other", "services")
		}},
		{"ambiguous-local-owner", func(_ *state.Object, r *[]managedDNSObservationCandidate) {
			other := (*r)[0]
			other.owner = root.Keys[0].Proof.New
			other.row.Reference = [32]byte{99}
			*r = append(*r, other)
		}},
		{"stale-one-pool", func(_ *state.Object, r *[]managedDNSObservationCandidate) {
			other := (*r)[0]
			other.row.Source.Revision--
			*r = append(*r, other)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidateRows := append([]managedDNSObservationCandidate(nil), rows...)
			o := object
			tc.change(&o, &candidateRows)
			if _, err := managedDNSObservationIdentity(key, o, members, root.Self.Key, candidateRows); err == nil {
				t.Fatal("invalid source selected a native DNS namespace")
			}
		})
	}
	// A remote owner's rows in a multi-node policy must not replace the local
	// original selection or create ambiguity between different physical nodes.
	foreign := rows[0]
	foreign.owner, foreign.row.Reference = [32]byte{99}, [32]byte{99}
	if owner, err := managedDNSObservationIdentity(key, object, members, root.Self.Key, append(rows, foreign)); err != nil || owner != root.OriginalKey() {
		t.Fatal("remote pool replaced exact local original owner", err)
	}
}

func TestManagedDNSObservationRemainsReadableWithoutCurrentWorkEligibility(t *testing.T) {
	root, members, key, object, rows := managedDNSObservationFixture(t)
	topology, err := lifecycle.New(root.Cluster, lifecycle.Configuration{Index: 1, Members: []lifecycle.Member{{ID: "node-c", Key: root.OriginalKey(), Voter: true}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, transition := range root.Keys {
		topology, err = topology.RotateIdentity(transition.Proof, transition.Index)
		if err != nil {
			t.Fatal(err)
		}
	}
	node, _ := topology.Node("node-c")
	topology, err = topology.Begin("node-c", "isolate-dns-owner", lifecycle.Isolate, node.Revision, topology.Epoch())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := topology.Encode()
	if err != nil {
		t.Fatal(err)
	}
	members.Runtime = &membership.RuntimeState{Topology: raw}
	if !members.MemberKey(root.Self.Key) || members.WorkKey(root.Self.Key) {
		t.Fatal("fixture did not isolate work while retaining membership")
	}
	if owner, err := managedDNSObservationIdentity(key, object, members, root.Self.Key, rows); err != nil || owner != root.OriginalKey() {
		t.Fatal("observation acquired an unintended WorkKey requirement", err)
	}
}
