// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"slices"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/workload"
)

// A server no administrator gave a node-wide limit uses everything it has
// (Jay 2026-11-27). Its default limit follows from the membership and is
// never written: an idle cluster commits nothing for it, and no user CAS
// sees its revision move. An administrator's limit replaces it.
func TestServerWithoutQuotaUsesAllItHas(t *testing.T) {
	f := newBackupCore(t)
	key := [32]byte(f.node.Public().(ed25519.PublicKey))
	r, err := f.p.Resources(f.s)
	if err != nil {
		t.Fatal(err)
	}
	limit, ok := r.Quotas.Limit("", "node-a")
	if !ok || !limit.Default || limit.Owner != key || limit.Revision != 0 || limit.Capacity != tenancy.DefaultCapacity || limit.Networks != tenancy.NewNodeLimit.Networks {
		t.Fatalf("default limit %+v", limit)
	}
	if got := f.p.SystemNetworkBlock(f.s, "node-a", key); got != "" {
		t.Fatal("blocked", got)
	}
	root := f.s.Object(ResourcesKey).Revision
	if _, ok := r.Quotas.Limit("", "node-gone"); ok {
		t.Fatal("a server outside the cluster has a default limit")
	}
	// the stored record holds no default limit
	raw, err := r.Quotas.Encode()
	if err != nil {
		t.Fatal(err)
	}
	stored, err := tenancy.DecodeQuotas(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := stored.Limit("", "node-a"); ok {
		t.Fatal("default limit stored")
	}
	if f.s.Object(ResourcesKey).Revision != root {
		t.Fatal("reading wrote")
	}

	// the first administrator limit says revision 0, as over no limit
	f.apply("admin-limit", "set-node-quota", 0, tenancy.NodeLimit{Node: "node-a", Capacity: workload.Resources{CPU: 6e9, Memory: 15 << 30}, Swap: 8 << 30, Networks: 16, MaxConsumers: 64, PacketQueuePackets: 256, PacketQueueBytes: 512 << 10, Default: true}, state.Applied)
	r, _ = f.p.Resources(f.s)
	limit, _ = r.Quotas.Limit("", "node-a")
	if limit.Default || limit.Swap != 8<<30 || limit.Capacity.Memory != 15<<30 || limit.Revision == 0 {
		t.Fatalf("administrator limit %+v", limit)
	}
	// swap is only part of the memory
	f.apply("swap-too-big", "set-node-quota", limit.Revision, tenancy.NodeLimit{Node: "node-a", Capacity: workload.Resources{CPU: 6e9, Memory: 4 << 30}, Swap: 8 << 30, Networks: 16}, state.ConditionFailed)
}

// A server that joined the system network on its default limit keeps a
// limit for its leftover rows once it is no full member any more (remove,
// force-remove leave its rows until it drains), so the resources still
// read; and after an identity rotation the default limit (current key)
// still owns rows made with the old key.
func TestDefaultQuotaCoversRowsOfARemovedOrRotatedServer(t *testing.T) {
	f := newBackupCore(t)
	b := joinTestNodeB(t, f)
	bkey := [32]byte(b.Public().(ed25519.PublicKey))
	networks := func() tenancy.Networks {
		t.Helper()
		r, err := f.p.Resources(f.s)
		if err != nil {
			t.Fatal(err)
		}
		return r.Networks
	}
	systemReport(t, f, f.node, "node-a", "use", true, networks().Revision(), nil, state.Applied)
	systemReport(t, f, b, "node-b", "join", false, networks().Revision(), nil, state.Applied)
	r, err := f.p.Resources(f.s)
	if err != nil {
		t.Fatal(err)
	}
	if members := r.Networks.SystemMembers(); len(members) != 2 {
		t.Fatalf("members %+v", members)
	}
	if limit, _ := r.Quotas.Limit("", "node-b"); !limit.Default || limit.Owner != bkey {
		t.Fatal("not on the default limit", limit)
	}

	// node-b leaves the membership; its system network row stays
	d, err := f.p.Members(f.s)
	if err != nil {
		t.Fatal(err)
	}
	d.Entries = slices.DeleteFunc(d.Entries, func(e membership.Entry) bool { return e.Peer.ID == "node-b" })
	d.Revision++
	writes, code := f.p.memberCheckpoint(f.s, d)
	if code != state.Applied {
		t.Fatal(code)
	}
	var applied state.Result
	f.s, applied, err = state.ApplyReduced(f.s, f.s.Index()+1, state.Command{Kind: state.Module, Actor: "anchor", Epoch: 1, RequestID: "mock-gone-b", Key: MembersKey, Expected: f.s.Object(MembersKey).Revision, Value: "fixture"}, nil, func(state.State, state.Command) (map[string][]byte, state.Code) { return writes, state.Applied })
	if err != nil || applied.Code != state.Applied {
		t.Fatal(applied, err)
	}
	if d, _ = f.p.Members(f.s); d.WorkKey(bkey) {
		t.Fatal("node-b is still a member")
	}
	r, err = f.p.Resources(f.s)
	if err != nil {
		t.Fatal("a removed server's rows break the resources", err)
	}
	if limit, ok := r.Quotas.Limit("", "node-b"); !ok || !limit.Default || limit.Owner != bkey {
		t.Fatal("leftover rows have no default limit", limit)
	}
	if r.Quotas.WithServerDefaults(map[string][32]byte{}).ValidateNetworks(r.Networks) == nil {
		t.Fatal("the rows need a limit; the test proves nothing")
	}

	// identity rotation: the default limit has the new key, the row the old
	key := [32]byte(f.node.Public().(ed25519.PublicKey))
	next := [32]byte{9}
	rotated, err := r.Quotas.RotateOwner(tenancy.OwnerRotation{Node: "node-a", Operation: "rotate-a", Old: key, New: next, Proof: [32]byte{1}, Index: f.s.Index() + 1})
	if err != nil {
		t.Fatal(err)
	}
	rotated = rotated.WithServerDefaults(map[string][32]byte{"node-a": next, "node-b": bkey})
	if limit, _ := rotated.Limit("", "node-a"); limit.Owner != next {
		t.Fatal("default owner", limit.Owner)
	}
	if err = rotated.ValidateNetworks(r.Networks); err != nil {
		t.Fatal("old-key row refused after rotation", err)
	}
	if _, err = rotated.Encode(); err != nil {
		t.Fatal(err)
	}
}
