// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
)

// Members remembers checkpoints that passed full validation. A repeated read
// returns the same directory as a fresh owned copy, and the memo never
// answers for another policy.
func TestMembersMemoReturnsOwnedCopiesPerPolicy(t *testing.T) {
	peer := func(id string, i int) config.Peer {
		seed := sha256.Sum256([]byte(fmt.Sprint("memo", i)))
		key := ed25519.NewKeyFromSeed(seed[:])
		return config.Peer{ID: id, Key: hex.EncodeToString(key.Public().(ed25519.PublicKey)), Endpoint: fmt.Sprintf("127.0.0.1:%d", 9100+i), Voter: i == 0}
	}
	genesis := peer("node-a", 0)
	var root [32]byte
	public, _ := hex.DecodeString(genesis.Key)
	copy(root[:], public)
	p := Policy{Cluster: [32]byte{81}, BootstrapKey: [32]byte{82}, TrustRoot: root, Genesis: genesis}
	d, err := membership.New(p.Cluster, genesis)
	if err != nil {
		t.Fatal(err)
	}
	if d, err = d.Invite(peer("node-b", 1), "join-b", nil); err != nil {
		t.Fatal(err)
	}
	s, _ := state.New("admin")
	writes, code := p.memberCheckpoint(s, d)
	if code != state.Applied {
		t.Fatal(code)
	}
	c := state.Command{Kind: state.Module, Actor: "admin", Epoch: 1, RequestID: "memo", Key: MembersKey, Value: "fixed-test-checkpoint"}
	s, result, err := state.ApplyReduced(s, 1, c, p.Validate, func(state.State, state.Command) (map[string][]byte, state.Code) { return writes, state.Applied })
	if err != nil || result.Code != state.Applied {
		t.Fatal(result, err)
	}
	first, err := p.Members(s)
	if err != nil || !reflect.DeepEqual(d, first) {
		t.Fatal("first read", err)
	}
	if !checkedMembers.has(p.membersKey(mustMembersRaw(t, p, s))) {
		t.Fatal("validated checkpoint was not remembered")
	}
	first.Entries[0].Peer.ID = "changed-by-caller"
	second, err := p.Members(s)
	if err != nil || !reflect.DeepEqual(d, second) {
		t.Fatal("memo read differs or shares the caller's copy", err)
	}
	other := p
	other.Cluster = [32]byte{83}
	if _, err = other.Members(s); err == nil {
		t.Fatal("memo answered for another cluster")
	}
}

func mustMembersRaw(t *testing.T, p Policy, s state.State) ([]byte, uint64) {
	t.Helper()
	raw, revision, err := readCheckpoint(s, MembersKey, p.Cluster, p.TrustRoot)
	if err != nil {
		t.Fatal(err)
	}
	return raw, revision
}
