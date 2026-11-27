// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/imagebuild"
)

// Corrupt rows enter through a test-only reducer without the product validator;
// hydration must reject them rather than relying on the row-producing path.
func TestHydrateBuildUploadRejectsMalformedSlotsCountsAndClosedRows(t *testing.T) {
	f, _ := imageBuildFixture(t)
	f.apply("manager", "begin-build-zip-upload", 0, ImageBuildUploadBegin{Tenant: "tenant", Context: "source", Upload: "hydrate", Length: 2 * imagebuild.PartBytes, Digest: sha256.Sum256([]byte("original injected ZIP")), ExpiresAt: 1000}, state.Applied)
	builds, err := f.p.ImageBuilds(f.s)
	if err != nil {
		t.Fatal(err)
	}
	begin, found := builds.Upload("tenant", "hydrate")
	if !found || begin.Scope.Parts() != 2 {
		t.Fatal("missing original two-slot upload")
	}
	prefix := buildPartPrefix("tenant", "hydrate")
	digest := sha256.Sum256([]byte("original injected part"))
	value := hex.EncodeToString(digest[:])
	for _, test := range []struct {
		name, suffix, value string
		received            uint32
		closed, remove, ok  bool
	}{
		{name: "canonical", suffix: "00000000", value: value, received: 1, ok: true},
		{name: "empty-index", value: value, received: 1},
		{name: "short-index", suffix: "0", value: value, received: 1},
		{name: "extra-zero", suffix: "000000000", value: value, received: 1},
		{name: "plus-index", suffix: "+0000000", value: value, received: 1},
		{name: "negative-index", suffix: "-0000000", value: value, received: 1},
		{name: "space-index", suffix: " 0000000", value: value, received: 1},
		{name: "index-suffix", suffix: "00000000tail", value: value, received: 1},
		{name: "index-overflow", suffix: "4294967296", value: value, received: 1},
		{name: "index-out-of-scope", suffix: "00000002", value: value, received: 1},
		{name: "non-hex", suffix: "00000000", value: strings.Repeat("z", 64), received: 1},
		{name: "upper-hex", suffix: "00000000", value: strings.ToUpper(value), received: 1},
		{name: "short-digest", suffix: "00000000", value: value[:62], received: 1},
		{name: "long-digest", suffix: "00000000", value: value + "00", received: 1},
		{name: "zero-digest", suffix: "00000000", value: strings.Repeat("0", 64), received: 1},
		{name: "count-too-small", suffix: "00000000", value: value},
		{name: "count-too-large", suffix: "00000000", value: value, received: 2},
		{name: "count-out-of-scope", suffix: "00000000", value: value, received: 3},
		{name: "closed-live-slot", suffix: "00000000", value: value, closed: true},
		{name: "open-malformed-tombstone", suffix: "not-an-index", value: "not-a-digest", remove: true, ok: true},
		{name: "closed-malformed-tombstone", suffix: "not-an-index", value: "not-a-digest", closed: true, remove: true, ok: true},
		{name: "removed-slot-count", suffix: "00000000", value: value, received: 1, remove: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, err := state.New("admin")
			if err != nil {
				t.Fatal(err)
			}
			key := prefix + test.suffix
			patch := func(id string, slot []byte) {
				t.Helper()
				cmd := state.Command{Kind: state.Module, Actor: "admin", Epoch: 1, RequestID: id, Key: ImageBuildKey, Expected: s.Object(ImageBuildKey).Revision}
				writes := map[string][]byte{ImageBuildKey: []byte("injected rows"), key: slot, buildPartPrefix("tenant", "unrelated") + "malformed": []byte("ignored other upload")}
				next, result, err := state.ApplyReduced(s, s.Index()+1, cmd, nil, func(state.State, state.Command) (map[string][]byte, state.Code) { return writes, state.Applied })
				if err != nil || result.Code != state.Applied {
					t.Fatal("inject hydration row", result, err)
				}
				s = next
			}
			patch("slot", []byte(test.value))
			if test.remove {
				patch("tombstone", nil)
			}
			record := begin
			record.Received, record.Closed = test.received, test.closed
			upload, err := hydrateBuildUpload(s, record)
			if !test.ok {
				if !errors.Is(err, ErrCatalog) {
					t.Fatal("malformed hydration row accepted", err)
				}
				return
			}
			if err != nil || upload.Validate() != nil || upload.Scope != begin.Scope || upload.Received != test.received || upload.Closed != test.closed {
				t.Fatal("valid hydration changed original scope/count/closed state", err)
			}
			if !test.remove && upload.Part(0) != digest {
				t.Fatal("canonical slot digest changed")
			}
		})
	}
}
