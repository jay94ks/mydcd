// SPDX-License-Identifier: Apache-2.0

package membership

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"github.com/jay94ks/mydcd/internal/config"
	"testing"
)

func TestCordonOnlyChangesSchedulingAndOwnsOriginalAcrossRestore(t *testing.T) {
	seed := sha256.Sum256([]byte("cordon-genesis"))
	private := ed25519.NewKeyFromSeed(seed[:])
	key := private.Public().(ed25519.PublicKey)
	peer := config.Peer{ID: "node-a", Key: hex.EncodeToString(key), Endpoint: "127.0.0.1:44001", Voter: true}
	original, err := New([32]byte{1}, peer)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"request":"original"}`)
	cordoned, err := original.SetCordon(peer.ID, 0, true, raw)
	if err != nil {
		t.Fatal(err)
	}
	raw[2] = 'X'
	if original.Cordon(peer.ID).Enabled || !cordoned.Cordon(peer.ID).Enabled || cordoned.Cordon(peer.ID).Revision != 1 || !cordoned.WorkKey([32]byte(key)) || !cordoned.MemberKey([32]byte(key)) || !bytes.Equal(cordoned.Cordons[0].Origin, []byte(`{"request":"original"}`)) {
		t.Fatal("cordon withdrew work/replication or aliased input")
	}
	entry, _ := cordoned.Entry(peer.ID)
	before, _ := original.Entry(peer.ID)
	if entry.Peer != before.Peer || entry.Revision != before.Revision || entry.Job != before.Job || entry.Phase != before.Phase {
		t.Fatal("cordon changed join/native generation")
	}
	encoded, err := cordoned.Encode()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = restored.SetCordon(peer.ID, 0, false, []byte(`{}`)); err == nil {
		t.Fatal("stale scheduling CAS admitted")
	}
	open, err := restored.SetCordon(peer.ID, 1, false, []byte(`{"request":"uncordon"}`))
	if err != nil || open.Cordon(peer.ID).Enabled || open.Cordon(peer.ID).Revision != 2 || !open.WorkKey([32]byte(key)) {
		t.Fatal("uncordon changed identity/work", err)
	}
	if _, err = open.SetCordon("missing", 0, true, []byte(`{}`)); err == nil {
		t.Fatal("unknown node cordoned")
	}
}
