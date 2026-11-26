// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestAppArtifactUploadImmutablePartsAndWholeDigest(t *testing.T) {
	raw := bytes.Repeat([]byte("original-content"), 4000)
	u, err := NewUpload("tenant", "app", "deploy", "alice", "original", len(raw), sha256.Sum256(raw))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = u.Complete(); err == nil {
		t.Fatal("incomplete artifact completed")
	}
	for i := len(u.Parts) - 1; i >= 0; i-- {
		part := bytes.Clone(raw[i*ArtifactPartBytes : min(len(raw), (i+1)*ArtifactPartBytes)])
		next, err := u.Add(i, part)
		if err != nil || len(u.Parts[i]) != 0 {
			t.Fatal("input mutation or rejected original part", err)
		}
		u = next
		part[0] ^= 1
		if _, err = u.Add(i, part); err == nil {
			t.Fatal("same part ID changed bytes")
		}
		if same, err := u.Add(i, u.Parts[i]); err != nil || same.Revision != u.Revision {
			t.Fatal("same original part not idempotent", err)
		}
	}
	encoded, err := u.Encode()
	if err != nil {
		t.Fatal(err)
	}
	u, err = DecodeUpload(encoded)
	if err != nil {
		t.Fatal(err)
	}
	complete, err := u.Complete()
	if err != nil || !bytes.Equal(complete, raw) {
		t.Fatal("whole original artifact lost", err)
	}
	complete[0] ^= 1
	if again, _ := u.Complete(); bytes.Equal(again, complete) {
		t.Fatal("caller changed retained artifact")
	}
	bad, _ := NewUpload("tenant", "app", "deploy", "alice", "bad-digest", 3, sha256.Sum256([]byte("abc")))
	if next, err := bad.Add(0, []byte("xyz")); err == nil || len(next.Parts[0]) != 0 {
		t.Fatal("incorrect whole digest published")
	}
	if _, err = u.Add(-1, []byte("x")); err == nil {
		t.Fatal("invalid part index")
	}
	if _, err = NewUpload("other/tenant", "app", "deploy", "alice", "id", 1, sha256.Sum256([]byte("x"))); err == nil {
		t.Fatal("foreign scope syntax")
	}
}
