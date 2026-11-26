// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"
)

func fixtureKey(n byte) (pub [32]byte, private ed25519.PrivateKey) {
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = n
	private = ed25519.NewKeyFromSeed(seed)
	copy(pub[:], private.Public().(ed25519.PublicKey))
	return
}
func fixtureConfig(index uint64, voters int) Configuration {
	c := Configuration{Index: index}
	for i, id := range []string{"node-a", "node-b", "node-c"} {
		key, _ := fixtureKey(byte(i + 1))
		c.Members = append(c.Members, Member{ID: id, Key: key, Voter: i < voters})
	}
	return c
}

func TestConcurrentRemovalReservationsCannotConsumeFinalVoter(t *testing.T) {
	s := topology(t)
	s = begin(t, s, "node-a", "remove-a", Remove)
	s = begin(t, s, "node-b", "remove-b", Remove)
	s = roundtrip(t, s)
	node, _ := s.Node("node-c")
	before, _ := s.Encode()
	next, err := s.Begin("node-c", "remove-c", Remove, node.Revision, s.Epoch())
	after, _ := next.Encode()
	if err == nil || !bytes.Equal(before, after) {
		t.Fatal("concurrent intents reserved the final voter/member")
	}
	// The read-only operation list is owned and cannot alter the product core.
	operations := s.Operations()
	operations[0].Action = Restore
	if s.Operations()[0].Action != Remove {
		t.Fatal("operation view aliases persisted core")
	}
	if s.Configuration().Voters() != 3 || s.Configuration().Quorum() != 2 {
		t.Fatal("removal intent changed native quorum")
	}
}
func topology(t *testing.T) Topology {
	t.Helper()
	c := fixtureConfig(1, 3)
	v, err := New([32]byte{1}, c)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func begin(t *testing.T, s Topology, node, id string, action Action) Topology {
	t.Helper()
	n, _ := s.Node(node)
	next, err := s.Begin(node, id, action, n.Revision, s.Epoch())
	if err != nil {
		t.Fatal(err)
	}
	return next
}
func receipt(t *testing.T, s Topology, node string) Proof {
	t.Helper()
	n, _ := s.Node(node)
	if n.Pending == nil {
		t.Fatal("no pending")
	}
	op := n.Pending
	p := Proof{Cluster: s.cluster, Node: node, Operation: op.ID, Generation: n.Generation, Revision: op.Revision, ConfigurationIndex: s.configuration.Index, Closed: op.Action != Restore, Ready: op.Action == Restore}
	return sign(p)
}
func sign(p Proof) Proof {
	var number byte
	switch p.Node {
	case "node-a":
		number = 1
	case "node-b":
		number = 2
	case "node-c":
		number = 3
	}
	_, key := fixtureKey(number)
	p.Signature = ed25519.Sign(key, ProofBytes(p))
	return p
}
func observe(t *testing.T, s Topology, p Proof) Topology {
	t.Helper()
	n, err := s.Observe(p)
	if err != nil {
		t.Fatal(err)
	}
	return n
}
func roundtrip(t *testing.T, s Topology) Topology {
	t.Helper()
	b, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	n, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	back, _ := n.Encode()
	if !bytes.Equal(b, back) {
		t.Fatal("roundtrip")
	}
	return n
}

func TestExplicitInitJoinAndSameRootResume(t *testing.T) {
	cluster := [32]byte{1}
	key, _ := fixtureKey(1)
	self := Member{ID: "node-a", Key: key, Voter: true}
	r, err := Prepare(Init, cluster, key, self, "init-one")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Installed.Members) != 0 || r.AppliedIndex != 0 {
		t.Fatal("configuration fabricated before SDK commit")
	}
	c := Configuration{Index: 1, Members: []Member{self}}
	r, err = r.Install(cluster, c, 1)
	if err != nil || !r.Installed.Standalone("node-a") || r.Installed.Quorum() != 1 {
		t.Fatal(r, err)
	}
	c.Members[0].ID = "mutated"
	if r.Installed.Members[0].ID != "node-a" {
		t.Fatal("configuration alias")
	}
	if err = r.Resume([32]byte{2}, self); err == nil {
		t.Fatal("other cluster resumed")
	}
	if err = r.Resume(cluster, self); err != nil {
		t.Fatal(err)
	}
	joined := self
	joined.Voter = false
	j, err := Prepare(Join, cluster, [32]byte{9}, joined, "join-one")
	if err != nil {
		t.Fatal(err)
	}
	config := fixtureConfig(2, 3)
	if _, err = j.Install(cluster, config, 2); err == nil {
		t.Fatal("join skipped non-voter install")
	}
	config.Members[0].Voter = false
	j, err = j.Install(cluster, config, 2)
	if err != nil {
		t.Fatal(err)
	}
	config.Index = 3
	config.Members[0].Voter = true
	j, err = j.Install(cluster, config, 3)
	if err != nil {
		t.Fatal(err)
	}
	if j.Installed.Standalone("node-a") || j.Installed.Quorum() != 2 {
		t.Fatal("connection count changed membership")
	}
	if _, err = j.Install([32]byte{2}, config, 3); err == nil {
		t.Fatal("cross-cluster install")
	}
	if _, err = j.Install(cluster, config, 2); err == nil {
		t.Fatal("configuration before durable state")
	}
	for _, intent := range []Intent{"", Intent("fallback")} {
		if _, err = Prepare(intent, cluster, key, self, "bad-init"); err == nil {
			t.Fatal(intent)
		}
	}
}

func TestStandaloneIsCommittedMembershipNotConnectivity(t *testing.T) {
	c := fixtureConfig(4, 1)
	if c.Standalone("node-a") || c.Quorum() != 1 {
		t.Fatal("non-voters mistaken for no members")
	}
	for voters, want := range map[int]int{1: 1, 2: 2, 3: 2} {
		c := fixtureConfig(4, voters)
		if c.Quorum() != want || c.Standalone("node-a") {
			t.Fatal(c)
		}
	}
	for _, bad := range []Configuration{{}, {Index: 1}, {Index: 1, Members: []Member{{ID: "node-a", Key: [32]byte{1}}}}} {
		if bad.Validate() == nil || bad.Quorum() != 0 {
			t.Fatal("invalid configuration", bad)
		}
	}
}

func TestIsolateRestoreRequiresOriginalSignedClosure(t *testing.T) {
	original := topology(t)
	s := begin(t, original, "node-b", "isolate-b", Isolate)
	if s.AdmitWork("node-b") || !original.AdmitWork("node-b") || s.Configuration().Quorum() != 2 {
		t.Fatal("isolation changed configuration/old view")
	}
	good := receipt(t, s, "node-b")
	for _, mutate := range []func(*Proof){
		func(p *Proof) { p.Resources = 1 }, func(p *Proof) { p.Flows = 1 }, func(p *Proof) { p.Writers = 1 }, func(p *Proof) { p.Leases = 1 }, func(p *Proof) { p.CDJobs = 1 },
		func(p *Proof) { p.Revision++ }, func(p *Proof) { p.Generation++ }, func(p *Proof) { p.ConfigurationIndex++ }, func(p *Proof) { p.Cluster = [32]byte{2} },
		func(p *Proof) { p.Closed = false; p.Ready = true }, func(p *Proof) { p.Operation = "other" },
	} {
		bad := good
		mutate(&bad)
		bad = sign(bad)
		if _, err := s.Observe(bad); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	bad := good
	bad.Signature = bytes.Repeat([]byte{1}, 64)
	if _, err := s.Observe(bad); err == nil {
		t.Fatal("forged signature")
	}
	s = roundtrip(t, s)
	n, _ := s.Node("node-b")
	if n.Phase != Isolating {
		t.Fatal("silence completed isolation")
	}
	s = observe(t, s, good)
	s = roundtrip(t, s)
	n, _ = s.Node("node-b")
	if n.Phase != Isolated || n.Pending != nil {
		t.Fatal(n)
	}
	if _, err := s.Observe(good); err == nil {
		t.Fatal("old closure replayed")
	}
	s = begin(t, s, "node-b", "restore-b", Restore)
	if _, err := s.Observe(good); err == nil {
		t.Fatal("closure used as restore")
	}
	p := receipt(t, s, "node-b")
	s = observe(t, s, p)
	s = roundtrip(t, s)
	if !s.AdmitWork("node-b") {
		t.Fatal("restore not admitted")
	}
	n, _ = s.Node("node-b")
	if _, err := s.Begin("node-b", "isolate-b", Isolate, n.Revision, s.Epoch()); err == nil {
		t.Fatal("old operation ID reused")
	}
}

func TestRemovalWaitsForClosureAndSDKConfiguration(t *testing.T) {
	s := begin(t, topology(t), "node-c", "remove-c", Remove)
	configuration := s.Configuration()
	configuration.Index = 2
	configuration.Members = configuration.Members[:2]
	if _, err := s.CommitConfiguration(s.cluster, configuration); err == nil {
		t.Fatal("removed before native closure")
	}
	s = observe(t, s, receipt(t, s, "node-c"))
	s = roundtrip(t, s)
	n, _ := s.Node("node-c")
	if n.Phase != Removing || len(s.Configuration().Members) != 3 {
		t.Fatal("closure forged SDK removal")
	}
	s, err := s.CommitConfiguration(s.cluster, configuration)
	if err != nil {
		t.Fatal(err)
	}
	s = roundtrip(t, s)
	n, _ = s.Node("node-c")
	if n.Phase != Removed || s.Configuration().Quorum() != 2 {
		t.Fatal(n)
	}
	one := Configuration{Index: 1, Members: fixtureConfig(1, 1).Members[:1]}
	single, err := New([32]byte{1}, one)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := single.Begin("node-a", "remove-last", Remove, 1, single.Epoch()); err == nil {
		t.Fatal("removed last voter/member")
	}
	nonvoter := fixtureConfig(1, 1)
	s, err = New([32]byte{1}, nonvoter)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Begin("node-a", "remove-last", Remove, 1, s.Epoch()); err == nil {
		t.Fatal("removed only voter with non-voters left")
	}
}

func TestSnapshotRejectsForgedLifecycleAndOwnsBuffers(t *testing.T) {
	s := begin(t, topology(t), "node-a", "isolate-a", Isolate)
	s = observe(t, s, receipt(t, s, "node-a"))
	n, _ := s.Node("node-a")
	n.Closure.Signature[0] ^= 1
	roundtrip(t, s)
	b, _ := s.Encode()
	for _, mutate := range []func(*topologyRecord){
		func(r *topologyRecord) { r.Schema = 2 }, func(r *topologyRecord) { r.Nodes[0].Closure = nil },
		func(r *topologyRecord) { r.Nodes[0].Phase = Active }, func(r *topologyRecord) { r.Nodes = append(r.Nodes, r.Nodes[0]) },
		func(r *topologyRecord) { r.Operations = nil }, func(r *topologyRecord) { r.Nodes[0].Closure.Generation++ },
	} {
		var r topologyRecord
		if err := json.Unmarshal(b, &r); err != nil {
			t.Fatal(err)
		}
		mutate(&r)
		raw, _ := json.Marshal(r)
		if _, err := Decode(raw); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	if _, err := Decode(append(b, ' ')); err == nil {
		t.Fatal("noncanonical snapshot")
	}
}

func TestOperationWindowRotationPreservesPendingAndRejectsOldEpoch(t *testing.T) {
	s := topology(t)
	before, _ := s.Node("node-b")
	s = begin(t, s, "node-a", "first-isolate", Isolate)
	if _, err := s.RotateOperations(s.Revision(), s.Epoch()); err == nil {
		t.Fatal("discarded pending operation")
	}
	s = observe(t, s, receipt(t, s, "node-a"))
	s = begin(t, s, "node-a", "first-restore", Restore)
	s = observe(t, s, receipt(t, s, "node-a"))
	oldEpoch := s.Epoch()
	n, err := s.RotateOperations(s.Revision(), oldEpoch)
	if err != nil {
		t.Fatal(err)
	}
	n = roundtrip(t, n)
	if n.Epoch() != oldEpoch+1 || len(n.operations) != 1 {
		t.Fatal("unsafe operation retention")
	}
	if _, err := n.Begin("node-b", "old-undispatched", Isolate, before.Revision, oldEpoch); err == nil {
		t.Fatal("old window admitted")
	}
	if _, err := n.Begin("node-b", "new-request", Isolate, before.Revision, n.Epoch()); err != nil {
		t.Fatal(err)
	}
}
