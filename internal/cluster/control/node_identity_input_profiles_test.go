// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"reflect"
	"testing"

	"github.com/jay94ks/mydcd/internal/secrets"
)

func TestRotatedInputProviderRetainsOriginalProfileAndRequiresExactNodeLineage(t *testing.T) {
	f := managedDNSTaskCoreFixture(t)
	c, err := f.p.Catalog(f.s)
	if err != nil {
		t.Fatal(err)
	}
	tree, err := secrets.NewTree(f.p.Cluster, "tenant", "root")
	if err != nil {
		t.Fatal(err)
	}
	profile := secrets.WriteProfile{ID: "values", Node: "node-a", Key: f.p.TrustRoot, Enabled: true, Values: true, Mode: "local-file"}
	tree, err = tree.SetWriteProfile(c, "admin", tree.Revision(), profile)
	if err != nil {
		t.Fatal(err)
	}
	plan := secrets.UsePlan{Leaves: []secrets.Leaf{{Reference: secrets.Reference{Profile: "values"}}}}
	want, err := f.p.inputProfiles(f.s, tree, plan)
	if err != nil || len(want) != 1 {
		t.Fatal("original provider", err)
	}
	before, err := tree.Encode()
	if err != nil {
		t.Fatal(err)
	}
	next := rotateRQ9CoreOwner(t, f)
	members, err := f.p.Members(f.s)
	current := [32]byte(next.Public().(ed25519.PublicKey))
	if err != nil || members.MemberKey(profile.Key) || !members.MemberKey(current) {
		t.Fatal("fixture did not revoke old current authentication", err)
	}
	got, err := f.p.inputProfiles(f.s, tree, plan)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("current provider lost immutable original profile/read-set", err)
	}
	after, err := tree.Encode()
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("provider resolution rewrote original metadata", err)
	}
	for _, test := range []struct {
		name string
		edit func(*secrets.WriteProfile)
	}{
		{"foreign-key", func(p *secrets.WriteProfile) { p.Key = [32]byte{99} }},
		{"wrong-node", func(p *secrets.WriteProfile) { p.Node = "node-b" }},
		{"disabled", func(p *secrets.WriteProfile) { p.Enabled = false }},
		{"not-values", func(p *secrets.WriteProfile) { p.Values, p.Verifiers, p.Mode = false, true, "vault" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			bad := profile
			test.edit(&bad)
			changed, err := tree.SetWriteProfile(c, "admin", tree.Revision(), bad)
			if err != nil {
				t.Fatal("counterexample profile", err)
			}
			if _, err := f.p.inputProfiles(f.s, changed, plan); err == nil {
				t.Fatal("foreign or disabled provider admitted")
			}
		})
	}
}
