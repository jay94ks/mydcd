// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
)

// Reuse the command fixture and shared Upload/receipt core. Only the native
// adapter's byte comparison changes to consume the original scope's split.
func chunkedBuildUploadCalls(f *buildUploadFixture, selected uint32) buildUploadCalls {
	api := f.adapters()
	api.chunkBytes = selected
	api.part = func(scope imagebuild.UploadScope, expected uint64, index uint32, data []byte) (control.ImageBuildIOResult, error) {
		f.partCalls[index]++
		f.expected = append(f.expected, expected)
		if scope != f.scope || expected != f.upload.Revision {
			return control.ImageBuildIOResult{}, errors.New("original chunk scope/CAS changed")
		}
		offset := int64(index) * scope.PartSize()
		if !bytes.Equal(data, f.body[offset:offset+int64(scope.PartLength(index))]) {
			return control.ImageBuildIOResult{}, errors.New("original chunk offset/bytes changed")
		}
		r := f.receipt(index, data)
		if err := f.put(r, expected); err != nil {
			return control.ImageBuildIOResult{}, err
		}
		return control.ImageBuildIOResult{Schema: 1, Scope: scope.Hash(), Code: "OK", Part: &r, Recorded: true, UploadRevision: f.upload.Revision}, nil
	}
	return api
}

func TestRegistryBuildUploadChunkSelectionAndFullTransfer(t *testing.T) {
	session := access.Session{Scopes: []access.Scope{{Tenant: "*", Actions: []access.Action{access.Read}}}}
	for i := 0; ; i++ {
		raw, err := json.Marshal(session)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) > 8<<10 {
			if buildUploadChunkBytes(session) != 0 {
				t.Fatal("large session selected a larger wire chunk")
			}
			break
		}
		if buildUploadChunkBytes(session) != imagebuild.UploadPartBytes {
			t.Fatal("bounded session did not select the new ZIP chunk")
		}
		session.Scopes = append(session.Scopes, access.Scope{Tenant: fmt.Sprintf("tenant-%03d", i), Actions: []access.Action{access.Read, access.ManageRegistry, access.ManageVolumes}})
	}
	for _, mode := range []string{"bounded-session", "large-session-fallback"} {
		t.Run(mode, func(t *testing.T) {
			f := newBuildUploadFixture(t, 6)
			selected := uint32(imagebuild.UploadPartBytes)
			if mode == "large-session-fallback" {
				selected = buildUploadChunkBytes(session)
			}
			f.scope.ChunkBytes = selected
			api := chunkedBuildUploadCalls(f, selected)
			mutate := api.mutate
			api.mutate = func(id, action string, expected, epoch uint64, payload any) (*state.Result, error) {
				if begin, ok := payload.(control.ImageBuildUploadBegin); ok && begin.ChunkBytes != selected {
					t.Fatal("new begin did not preserve chosen chunk size")
				}
				return mutate(id, action, expected, epoch, payload)
			}
			result, err := f.run(api)
			if err != nil || !f.upload.Closed || f.upload.Scope.ChunkBytes != selected || result["bytes"] != int64(len(f.body)) || f.seals != 1 || len(f.partCalls) != int(f.scope.Parts()) {
				t.Fatal("actual command transfer split/seal/CAS changed", result, err)
			}
			if mode == "bounded-session" && (f.scope.PartSize() != imagebuild.UploadPartBytes || len(f.partCalls) >= 6) || mode == "large-session-fallback" && (f.scope.PartSize() != imagebuild.PartBytes || len(f.partCalls) != 6) {
				t.Fatal("new chunk/fallback used wrong fixed offsets", f.scope.PartSize(), len(f.partCalls))
			}
			consume := f.originals[f.options.Prefix+"-consume"]
			var q control.ImageBuildZIPConsume
			if json.Unmarshal(consume.Payload, &q) != nil || !q.Fact.Valid(f.scope) || q.Fact.ZIP != sha256.Sum256(f.body) || consume.Expected != uint64(f.scope.Parts())+1 {
				t.Fatal("final seal or consume lost original whole ZIP/chunk scope/CAS")
			}
			begin := bytes.Clone(f.originals[f.options.Prefix+"-begin"].Payload)
			if selected == 0 && bytes.Contains(begin, []byte("ChunkBytes")) || selected != 0 && !bytes.Contains(begin, []byte(`"ChunkBytes":32768`)) {
				t.Fatal("legacy optional JSON or new begin chunk changed")
			}
			if _, err := f.run(api); err != nil || !bytes.Equal(begin, f.originals[f.options.Prefix+"-begin"].Payload) || len(f.mutations) != 2 {
				t.Fatal("consumed original recreated or changed chunk size", err)
			}
			assertBuildUploadManagement(t, f, "begin-build-zip-upload", "upload-build-zip")
		})
	}
}

func TestRegistryBuildUploadChunkResumeNeverReplansOriginal(t *testing.T) {
	for _, original := range []uint32{0, imagebuild.UploadPartBytes} {
		t.Run(fmt.Sprint(original), func(t *testing.T) {
			f := newBuildUploadFixture(t, 4)
			f.scope.ChunkBytes = original
			api := chunkedBuildUploadCalls(f, original)
			part := api.part
			api.part = func(s imagebuild.UploadScope, e uint64, i uint32, b []byte) (control.ImageBuildIOResult, error) {
				if _, err := part(s, e, i, b); err != nil {
					return control.ImageBuildIOResult{}, err
				}
				return control.ImageBuildIOResult{}, &userauth.Error{Code: "transport", Phase: sfcp.Unknown}
			}
			if _, err := f.run(api); err == nil || f.upload.Received != 1 || f.partCalls[0] != 1 || f.seals != 0 {
				t.Fatal("unconfirmed first chunk was retried or sealed", err)
			}
			begin := bytes.Clone(f.originals[f.options.Prefix+"-begin"].Payload)
			originalScope := f.upload.Scope
			// Selection is now the opposite size, as after re-login or a new CLI.
			selected := uint32(imagebuild.UploadPartBytes)
			if original != 0 {
				selected = 0
			}
			api = chunkedBuildUploadCalls(f, selected)
			if _, err := f.run(api); err == nil || f.partCalls[0] != 1 {
				t.Fatal("unknown original resumed implicitly", err)
			}
			f.options.Resume = true
			if _, err := f.run(api); err != nil || !f.upload.Closed || f.upload.Scope != originalScope || !bytes.Equal(begin, f.originals[f.options.Prefix+"-begin"].Payload) || f.partCalls[0] != 2 {
				t.Fatal("explicit resume changed original chunk/signing payload", err)
			}
			assertBuildUploadManagement(t, f, "begin-build-zip-upload", "upload-build-zip")
		})
	}
}

func TestRegistryBuildUploadRejectsChunkScopeJournalMismatch(t *testing.T) {
	for _, change := range []string{"journal", "scope"} {
		t.Run(change, func(t *testing.T) {
			f := newBuildUploadFixture(t, 3)
			f.start()
			id := f.options.Prefix + "-begin"
			before := f.originals[id]
			if change == "journal" {
				var begin control.ImageBuildUploadBegin
				if json.Unmarshal(before.Payload, &begin) != nil {
					t.Fatal("original begin missing")
				}
				begin.ChunkBytes = imagebuild.UploadPartBytes
				f.remember(id, before.Action, before.Expected, begin)
			} else {
				f.upload.Scope.ChunkBytes = imagebuild.UploadPartBytes
			}
			original := f.originals[id]
			f.options.Resume = true
			if _, err := f.run(chunkedBuildUploadCalls(f, imagebuild.UploadPartBytes)); err == nil || len(f.partCalls) != 0 || len(f.mutations) != 0 || !reflect.DeepEqual(original, f.originals[id]) {
				t.Fatal("mismatched original chunk accepted or replaced", err)
			}
		})
	}
}
