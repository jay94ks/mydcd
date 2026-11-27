// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
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
		d, err = d.Invite(makePeer(fmt.Sprintf("node-%03d", i), i, false), fmt.Sprintf("join-%03d", i), nil)
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
	// A candidate whose root references a blob it deletes.
	partial := maps.Clone(writes)
	partial[recordPart(t, writes, MembersKey)] = nil
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

// A reduction that shrinks another namespace's checkpoint deletes the blobs
// it no longer uses. Patch admission must take those removals.
func TestCheckpointPatchKeyTakesShrinkingParts(t *testing.T) {
	p := Policy{Cluster: [32]byte{71}, TrustRoot: [32]byte{73}}
	empty, _ := state.New("admin")
	record := func(c byte) string { return `{"V":"` + strings.Repeat(string(c), blobPartSize) + `"}` }
	raw := []byte(`{"Rows":[` + record('a') + "," + record('b') + `],"Revision":1}`)
	big, code := writeCheckpoint(empty, MembersKey, p.Cluster, p.TrustRoot, 1, raw)
	if code != state.Applied || len(big) != 6 {
		t.Fatal("two two-part blobs, skeleton and root", code, len(big))
	}
	c := state.Command{Kind: state.Module, Actor: "admin", Epoch: 1, RequestID: "members", Key: MembersKey, Value: "fixed-test-checkpoint"}
	s, result, err := state.ApplyReduced(empty, 1, c, nil, func(state.State, state.Command) (map[string][]byte, state.Code) { return big, state.Applied })
	if err != nil || result.Code != state.Applied {
		t.Fatal("seed checkpoint", result, err)
	}
	if got, _, err := readCheckpoint(s, MembersKey, p.Cluster, p.TrustRoot); err != nil || !bytes.Equal(got, raw) {
		t.Fatal("round trip", err)
	}
	// Dropping one record rewrites only the skeleton and deletes its blob.
	small, code := writeCheckpoint(s, MembersKey, p.Cluster, p.TrustRoot, 2, []byte(`{"Rows":[`+record('a')+`],"Revision":2}`))
	removed := 0
	for key, value := range small {
		if value == nil {
			removed++
		} else if key != MembersKey && len(value) == blobPartSize {
			t.Fatal("rewrote an unchanged record", key)
		}
		if !checkpointPatchKey(small, MembersKey, key) {
			t.Fatal("refused own checkpoint key", key)
		}
	}
	if code != state.Applied || removed != 3 {
		t.Fatal("shrunk checkpoint must remove the old skeleton and record", code, removed)
	}
	if checkpointPatchKey(small, MembersKey, MembersKey+"/absent/0") || checkpointPatchKey(small, MembersKey, AppsKey) || checkpointPatchKey(map[string][]byte{MembersKey: nil}, MembersKey, MembersKey) {
		t.Fatal("admitted a key that is not this written checkpoint")
	}
}

// recordPart is a blob part that writes stores for root, other than the
// skeleton's.
func recordPart(t testing.TB, writes map[string][]byte, root string) string {
	var header checkpointRoot
	if err := json.Unmarshal(writes[root], &header); err != nil {
		t.Fatal(err)
	}
	skeleton, _, _ := parseBlobRef(header.Skeleton)
	keys := slices.Sorted(maps.Keys(writes))
	for _, key := range keys {
		if strings.HasPrefix(key, root+"/") && writes[key] != nil && !strings.HasPrefix(key, root+"/"+skeleton+"/") {
			return key
		}
	}
	t.Fatal("no record blob written")
	return ""
}

// storedPart is a present blob part of the checkpoint at root in s.
func storedPart(t testing.TB, s state.State, root string) string {
	keys := slices.Sorted(maps.Keys(s.Objects(root + "/")))
	for _, key := range keys {
		if s.Object(key).Present {
			return key
		}
	}
	t.Fatal("no stored part")
	return ""
}

// A large collection is stored in content-defined groups, so inserting one
// record rewrites its group and the skeleton, not every reference (R17 B2).
func TestCheckpointGroupsLargeCollections(t *testing.T) {
	p := Policy{Cluster: [32]byte{71}, TrustRoot: [32]byte{73}}
	type record struct{ ID, Body string }
	book := func(n int, extra bool) []byte {
		var rows []record
		for i := 0; i < n; i++ {
			rows = append(rows, record{fmt.Sprintf("r-%04d", i), strings.Repeat("x", 200)})
			if extra && i == n/2 {
				rows = append(rows, record{"inserted", strings.Repeat("y", 200)})
			}
		}
		m := map[string]record{}
		for _, r := range rows[:300] {
			m[r.ID] = r
		}
		raw, _ := json.Marshal(struct {
			Rows   []record
			ByID   map[string]record
			Note   string
			Values []int
		}{rows, m, "n", []int{1, 2, 3}})
		return raw
	}
	empty, _ := state.New("admin")
	raw := book(1000, false)
	writes, code := writeCheckpoint(empty, AppsKey, p.Cluster, p.TrustRoot, 1, raw)
	c := state.Command{Kind: state.Module, Actor: "admin", Epoch: 1, RequestID: "seed", Key: AppsKey, Value: "seed"}
	s, result, err := state.ApplyReduced(empty, 1, c, nil, func(state.State, state.Command) (map[string][]byte, state.Code) { return writes, code })
	if err != nil || result.Code != state.Applied {
		t.Fatal(result, err)
	}
	if got, _, err := readCheckpoint(s, AppsKey, p.Cluster, p.TrustRoot); err != nil || !bytes.Equal(got, raw) {
		t.Fatal("grouped round trip", err)
	}
	next := book(1000, true)
	writes, code = writeCheckpoint(s, AppsKey, p.Cluster, p.TrustRoot, 2, next)
	written := 0
	for _, v := range writes {
		written += len(v)
	}
	if code != state.Applied || written*10 > len(next) {
		t.Fatal("insertion rewrote too much", code, written, len(next))
	}
	c.RequestID, c.Expected = "insert", result.Revision
	s, result, err = state.ApplyReduced(s, 2, c, nil, func(state.State, state.Command) (map[string][]byte, state.Code) { return writes, code })
	if err != nil || result.Code != state.Applied {
		t.Fatal(result, err)
	}
	if got, _, err := readCheckpoint(s, AppsKey, p.Cluster, p.TrustRoot); err != nil || !bytes.Equal(got, next) {
		t.Fatal("insert round trip", err)
	}
	// A stray object under the root is refused.
	c.RequestID, c.Expected = "stray", result.Revision
	bad, _, _ := state.ApplyReduced(s, 3, c, nil, func(state.State, state.Command) (map[string][]byte, state.Code) {
		return map[string][]byte{AppsKey: writes[AppsKey], AppsKey + "/stray/0": []byte("x")}, state.Applied
	})
	if bad.Object(AppsKey+"/stray/0").Revision == 0 {
		t.Fatal("stray fixture not applied")
	}
	if _, _, err := readCheckpoint(bad, AppsKey, p.Cluster, p.TrustRoot); err == nil {
		t.Fatal("stray object accepted")
	}
}
