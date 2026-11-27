// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/imagebuild"
)

// Same production reducer, receipt verification and snapshot validator as
// ordinary uploads. Native ZIP/file I/O is covered by the spool source tests.
func TestImageBuildExplicitChunkScopeCASPartialRestoreAndLegacyCoexistence(t *testing.T) {
	f, spec := imageBuildFixture(t)
	data := bytes.Repeat([]byte{37}, 2*imagebuild.UploadPartBytes+7)
	begin := ImageBuildUploadBegin{Tenant: "tenant", Context: spec.ID, Upload: "chunk32", Length: int64(len(data)), Digest: sha256.Sum256(data), ExpiresAt: 1000, ChunkBytes: imagebuild.UploadPartBytes}
	f.apply("manager", "begin-build-zip-upload", 0, begin, state.Applied)
	book, err := f.p.ImageBuilds(f.s)
	if err != nil {
		t.Fatal(err)
	}
	original, _ := book.Upload("tenant", begin.Upload)
	if original.Scope.ChunkBytes != begin.ChunkBytes || original.Scope.Parts() != 3 || original.Scope.PartLength(2) != 7 {
		t.Fatal("begin did not retain explicit immutable chunk size")
	}
	legacy := begin
	legacy.Upload, legacy.ChunkBytes = "legacy24", 0
	f.apply("manager", "begin-build-zip-upload", 0, legacy, state.Applied)
	legacyJSON, _ := json.Marshal(legacy)
	if bytes.Contains(legacyJSON, []byte("ChunkBytes")) {
		t.Fatal("legacy begin changed original signed JSON")
	}
	for _, index := range []uint32{2, 0, 1} {
		book, _ = f.p.ImageBuilds(f.s)
		u, _ := book.Upload("tenant", begin.Upload)
		start := int64(index) * u.Scope.PartSize()
		part := buildTestPart(t, f, begin.Upload, index, data[start:start+int64(u.Scope.PartLength(index))])
		f.apply("manager", "put-build-zip-part", u.Revision, part, state.Applied)
		book, _ = f.p.ImageBuilds(f.s)
		u, _ = book.Upload("tenant", begin.Upload)
		revision := u.Revision
		f.apply("manager", "put-build-zip-part", revision, part, state.Applied)
		book, _ = f.p.ImageBuilds(f.s)
		u, _ = book.Upload("tenant", begin.Upload)
		if u.Revision != revision || u.Scope != original.Scope {
			t.Fatal("duplicate part advanced CAS or changed original scope")
		}
		raw, err := state.Encode(f.s)
		if err != nil {
			t.Fatal(err)
		}
		restored, err := state.Decode(raw)
		if err != nil || f.p.Validate(state.State{}, restored, state.Command{}) != nil {
			t.Fatal("partial chunk-size restore", err)
		}
		f.s = restored
	}
	book, _ = f.p.ImageBuilds(f.s)
	u, _ := book.Upload("tenant", begin.Upload)
	old, _ := book.Upload("tenant", legacy.Upload)
	if old.Scope.ChunkBytes != 0 || old.Scope.PartSize() != imagebuild.PartBytes || old.Received != 0 {
		t.Fatal("new upload changed coexistence legacy scope/slots")
	}
	seal := buildTestSeal(t, f, begin.Upload)
	f.apply("manager", "upload-build-zip", u.Revision, ImageBuildZIPConsume{Tenant: "tenant", ID: spec.ID, Upload: begin.Upload, Fact: seal}, state.Applied)
	book, _ = f.p.ImageBuilds(f.s)
	closed, _ := book.Upload("tenant", begin.Upload)
	if !closed.Closed || closed.Version != imagebuild.VersionID(seal) || closed.Scope != original.Scope || closed.Received != 0 {
		t.Fatal("original 32 KiB seal/consumer was replaced")
	}
	// A caller cannot reinterpret the accepted legacy ID with the new size.
	legacy.ChunkBytes = imagebuild.UploadPartBytes
	f.apply("manager", "begin-build-zip-upload", 0, legacy, state.ConditionFailed)
	book, _ = f.p.ImageBuilds(f.s)
	retained, _ := book.Upload("tenant", legacy.Upload)
	if retained.Scope != old.Scope || retained.Begin.RequestID != old.Begin.RequestID {
		t.Fatal("legacy original recreated with new fixed offsets")
	}
}

func TestImageBuildChunkSizeRestoreAndReceiptCannotDivergeFromOriginalBegin(t *testing.T) {
	for _, size := range []uint32{0, imagebuild.UploadPartBytes} {
		f, spec := imageBuildFixture(t)
		begin := ImageBuildUploadBegin{Tenant: "tenant", Context: spec.ID, Upload: "original-size", Length: 17, Digest: sha256.Sum256([]byte("whole native archive")), ExpiresAt: 1000, ChunkBytes: size}
		f.apply("manager", "begin-build-zip-upload", 0, begin, state.Applied)
		book, _ := f.p.ImageBuilds(f.s)
		original, _ := book.Upload("tenant", begin.Upload)
		changed := original
		if size == 0 {
			changed.Scope.ChunkBytes = imagebuild.UploadPartBytes
		} else {
			changed.Scope.ChunkBytes = 0
		}
		// Length/part count are deliberately unchanged. Only the immutable
		// original begin/Scope binding can reject this checkpoint mutation.
		raw, _ := json.Marshal(changed)
		cmd := state.Command{Kind: state.Module, Actor: "anchor", Epoch: f.s.ModuleEpoch(), RequestID: "forged-chunk-checkpoint", Key: ImageBuildKey, Expected: f.s.Object(ImageBuildKey).Revision, Value: "declared invalid candidate"}
		_, result, err := state.ApplyReduced(f.s, f.s.Index()+1, cmd, f.p.Validate, func(state.State, state.Command) (map[string][]byte, state.Code) {
			return map[string][]byte{buildRecordKey("upload", "tenant", begin.Upload): raw}, state.Applied
		})
		if err != nil || result.Code != state.Invalid {
			t.Fatal("restore changed original accepted chunk size", size, result.Code, err)
		}
		part := buildTestPart(t, f, begin.Upload, 0, bytes.Repeat([]byte{1}, 17))
		part.Receipt.Scope = changed.Scope.Hash()
		part.Receipt.Signature = ed25519.Sign(f.node, imagebuild.PartReceiptBytes(part.Receipt))
		f.apply("manager", "put-build-zip-part", 1, part, state.ConditionFailed)
	}
	for _, size := range []uint32{1, imagebuild.PartBytes, imagebuild.UploadPartBytes + 1} {
		q := ImageBuildUploadBegin{Tenant: "tenant", Context: "source", Upload: "invalid", Length: 17, Digest: [32]byte{1}, ExpiresAt: 1000, ChunkBytes: size}
		raw, _ := json.Marshal(q)
		if _, _, err := buildChangeSelection(Change{Action: "begin-build-zip-upload", Payload: raw}); err == nil {
			t.Fatal("unsupported explicit chunk size admitted", size)
		}
	}
}
