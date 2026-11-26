// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/membership"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/config"
)

func TestMemberCheckpointBoundedRowsAndStrictRestore(t *testing.T) {
	makePeer := func(id string, i int, voter bool) config.Peer {
		seed := sha256.Sum256([]byte(fmt.Sprint(i)))
		key := ed25519.NewKeyFromSeed(seed[:])
		return config.Peer{ID: id, Key: hex.EncodeToString(key.Public().(ed25519.PublicKey)), Endpoint: fmt.Sprintf("127.0.0.1:%d", 9000+i), Voter: voter}
	}
	genesis := makePeer("node-a", 0, true)
	var root [32]byte
	public, _ := hex.DecodeString(genesis.Key)
	copy(root[:], public)
	p := Policy{Cluster: [32]byte{71}, BootstrapKey: [32]byte{72}, TrustRoot: root, Genesis: genesis}
	d, err := membership.New(p.Cluster, genesis)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 80; i++ {
		d, err = d.Invite(makePeer(fmt.Sprintf("node-%03d", i), i, false), fmt.Sprintf("join-%03d", i))
		if err != nil {
			t.Fatal(err)
		}
	}
	raw, err := d.Encode()
	if err != nil || len(raw) <= 64<<10 {
		t.Fatal("fixture does not exercise large directory", len(raw), err)
	}
	s, _ := state.New("admin")
	writes, code := p.memberCheckpoint(s, d)
	if code != state.Applied || len(writes) < 4 {
		t.Fatal("not chunked", code, len(writes))
	}
	for key, value := range writes {
		if len(value) > 32<<10 {
			t.Fatal("row exceeds selected chunk budget", key, len(value))
		}
	}
	c := state.Command{Kind: state.Module, Actor: "admin", Epoch: 1, RequestID: "checkpoint", Key: MembersKey, Value: "fixed-test-checkpoint"}
	n, result, err := state.ApplyReduced(s, 1, c, p.Validate, func(state.State, state.Command) (map[string][]byte, state.Code) { return writes, state.Applied })
	if err != nil || result.Code != state.Applied {
		t.Fatal("atomic checkpoint rejected", result, err)
	}
	encoded, err := state.Encode(n)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := state.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.Members(restored)
	if err != nil || !reflect.DeepEqual(d, got) {
		t.Fatal("complete checkpoint failed restore", err)
	}
	current, err := p.Current(restored)
	if err != nil || len(current.Issuers) != 1 || !current.Issuer(root).Enabled {
		t.Fatal("invitations changed issuers", err)
	}
	// A candidate replacing only the root/one part has mixed committed ordinals.
	partial := map[string][]byte{MembersKey: bytes.Clone(writes[MembersKey]), partKey(MembersKey, 0): bytes.Clone(writes[partKey(MembersKey, 0)])}
	c.RequestID, c.Expected = "partial", result.Revision
	bad, rejected, err := state.ApplyReduced(n, 2, c, p.Validate, func(state.State, state.Command) (map[string][]byte, state.Code) { return partial, state.Applied })
	if err != nil || rejected.Code != state.Invalid || bad.Object(MembersKey) != n.Object(MembersKey) {
		t.Fatal("partial chunk patch escaped rollback", rejected, err)
	}
	untrusted, _, err := state.ApplyReduced(n, 2, c, nil, func(state.State, state.Command) (map[string][]byte, state.Code) { return partial, state.Applied })
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.Members(untrusted); err == nil {
		t.Fatal("mixed revision root decoded")
	}
	foreign := p
	foreign.TrustRoot = [32]byte{99}
	if _, err = foreign.Members(restored); err == nil {
		t.Fatal("changed genesis trust accepted")
	}
}

// A reduction that shrinks another namespace's checkpoint deletes its last
// parts. Patch admission must take those removals, or the report is refused.
func TestCheckpointPatchKeyTakesShrinkingParts(t *testing.T) {
	p := Policy{Cluster: [32]byte{71}, TrustRoot: [32]byte{73}}
	empty, _ := state.New("admin")
	big, code := writeCheckpoint(empty, MembersKey, p.Cluster, p.TrustRoot, 1, bytes.Repeat([]byte{'x'}, 3*catalogPartSize))
	if code != state.Applied || len(big) != 4 {
		t.Fatal("three-part checkpoint", code, len(big))
	}
	c := state.Command{Kind: state.Module, Actor: "admin", Epoch: 1, RequestID: "members", Key: MembersKey, Value: "fixed-test-checkpoint"}
	s, result, err := state.ApplyReduced(empty, 1, c, nil, func(state.State, state.Command) (map[string][]byte, state.Code) { return big, state.Applied })
	if err != nil || result.Code != state.Applied {
		t.Fatal("seed checkpoint", result, err)
	}
	small, code := writeCheckpoint(s, MembersKey, p.Cluster, p.TrustRoot, 2, []byte("{}"))
	if code != state.Applied || small[partKey(MembersKey, 1)] != nil || small[partKey(MembersKey, 2)] != nil {
		t.Fatal("shrunk checkpoint must remove its last parts", code)
	}
	for key := range small {
		if !checkpointPatchKey(small, MembersKey, key) {
			t.Fatal("refused own checkpoint key", key)
		}
	}
	if checkpointPatchKey(small, MembersKey, partKey(MembersKey, 3)) || checkpointPatchKey(small, MembersKey, AppsKey) || checkpointPatchKey(map[string][]byte{MembersKey: nil}, MembersKey, MembersKey) {
		t.Fatal("admitted a key that is not this written checkpoint")
	}
}
