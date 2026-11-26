// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"slices"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
)

func TestPartProofSurvivesRelayWithoutAllowingDifferentBytesOrCreator(t *testing.T) {
	data := []byte("part")
	scope, _ := testScope(int64(len(data)), sha256.Sum256(data))
	key := ed25519.NewKeyFromSeed(slices.Repeat([]byte{8}, 32))
	session := access.Session{Schema: 1, Cluster: scope.Cluster, User: scope.Creator, Key: [32]byte(key.Public().(ed25519.PublicKey)), IssuedAt: 1, ExpiresAt: 1000}
	p := PartProof{Schema: 1, Scope: scope.Hash(), Index: 0, Length: uint32(len(data)), Digest: sha256.Sum256(data), Expected: 1, At: 100, ExpiresAt: 200, Nonce: [32]byte{1}}
	p.Signature = ed25519.Sign(key, PartProofBytes(p))
	q := Transfer{Upload: scope.Upload, Kind: "part", Expected: 1, Data: data, Proof: &p}
	if err := q.Authorize(scope, session, 101); err != nil {
		t.Fatal(err)
	}
	changed := q
	changed.Data = []byte("evil")
	if changed.Authorize(scope, session, 101) == nil {
		t.Fatal("relay changed body")
	}
	changed = q
	changed.Expected++
	if changed.Authorize(scope, session, 101) == nil {
		t.Fatal("relay changed upload CAS")
	}
	other := scope
	other.Context = "other"
	if q.Authorize(other, session, 101) == nil {
		t.Fatal("proof moved to other context")
	}
	otherUser := session
	otherUser.User = "bob"
	if q.Authorize(scope, otherUser, 101) == nil {
		t.Fatal("proof moved to another account")
	}
	if q.Authorize(scope, session, 200) == nil {
		t.Fatal("expired proof accepted")
	}
	if (Transfer{Upload: scope.Upload, Kind: "seal", Expected: 1, Data: data}).Valid() {
		t.Fatal("seal carries a second raw input")
	}
	if bytes.Contains(PartProofBytes(p), []byte(`"Record"`)) {
		t.Fatal("default recording mode changed original schema-1 proof bytes")
	}
	old := struct {
		Schema        uint8
		Scope         [32]byte
		Index, Length uint32
		Digest        [32]byte
		Expected      uint64
		At, ExpiresAt int64
		Nonce         [32]byte
		Signature     []byte
	}{p.Schema, p.Scope, p.Index, p.Length, p.Digest, p.Expected, p.At, p.ExpiresAt, p.Nonce, nil}
	raw, _ := json.Marshal(old)
	if !bytes.Equal(PartProofBytes(p), append([]byte("mydc-imagebuild-part-request-1\x00"), raw...)) {
		t.Fatal("legacy exact user proof signing bytes changed")
	}
	changed = q
	changed.Record = true
	if changed.Valid() || changed.Authorize(scope, session, 101) == nil {
		t.Fatal("relay enabled shared progress without user consent")
	}
	recorded := p
	recorded.Record = true
	digest := PartSessionDigest(session)
	recorded.Session = &digest
	changed.Proof = &recorded
	if changed.Authorize(scope, session, 101) == nil {
		t.Fatal("unsigned recording mode accepted")
	}
	recorded.Signature = ed25519.Sign(key, PartProofBytes(recorded))
	if changed.Authorize(scope, session, 101) != nil || recorded.Authorize(scope, session, 101) != nil {
		t.Fatal("signed recording mode rejected by transfer/report core")
	}
	otherSession := session
	otherSession.ID = "another-grant"
	if recorded.Authorize(scope, otherSession, 101) == nil {
		t.Fatal("recorded proof moved to another session ceiling")
	}
}
