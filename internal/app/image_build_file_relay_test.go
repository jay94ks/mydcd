// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/nodestorage"
)

func TestDraftFileOwnerRelayKeepsConflictAndRejectsWrongKindsOrMixedResults(t *testing.T) {
	scope := imagebuild.DraftScope{Schema: 1, Tenant: "tenant", Context: "source", Root: nodestorage.Reference{Cluster: [32]byte{1}, Node: "node-a", Key: [32]byte{2}, ID: "disk", Generation: 1, Path: "/srv/mydc"}, ContextRevision: 1, PolicyRevision: 1, Dockerfile: "Dockerfile", ExpandedLimit: 1 << 20}
	q := imagebuild.DraftRequest{Context: scope.Context, Kind: "file", Scope: &scope, Revision: 2, Digest: &[32]byte{4}, Path: "composer.json"}
	for _, cause := range []error{imagebuild.ErrConflict, imagebuild.ErrInvalid, access.ErrDenied} {
		raw, _ := json.Marshal(imageBuildFileOwnerReply{Code: imageBuildFileReadCode(errors.Join(cause, errors.New("private /srv/owner/key path")))})
		if bytes.Contains(raw, []byte("private")) || bytes.Contains(raw, []byte("/srv")) {
			t.Fatal("native error detail disclosed")
		}
		if _, err := decodeImageBuildFileDraft(raw, q, scope); !errors.Is(err, cause) {
			t.Fatal("owner error category lost", err)
		}
	}
	valid := imagebuild.DraftResponse{Schema: 1, Scope: scope, Code: "OK", Revision: q.Revision, Digest: q.Digest, Content: &imagebuild.FilePage{Entry: imagebuild.Entry{Path: q.Path, Bytes: 1, Digest: [32]byte{5}}, Total: 1, Data: []byte("x")}}
	raw, _ := json.Marshal(imageBuildFileOwnerReply{Code: "ok", Draft: &valid})
	if _, err := decodeImageBuildFileDraft(raw, q, scope); err != nil {
		t.Fatal("original file reply rejected", err)
	}
	wrong := q
	wrong.Kind = "tree"
	wrong.Path = ""
	if _, err := decodeImageBuildFileDraft(raw, wrong, scope); err == nil {
		t.Fatal("tree borrowed file relay response")
	}
	other := scope
	other.Tenant = "other"
	if _, err := decodeImageBuildFileDraft(raw, q, other); err == nil {
		t.Fatal("foreign scope borrowed original response")
	}
	for _, reply := range []imageBuildFileOwnerReply{{Code: "conflict", Draft: &valid}, {Code: "ok"}, {Code: "unexpected", Draft: &valid}} {
		raw, _ := json.Marshal(reply)
		if _, err := decodeImageBuildFileDraft(raw, q, scope); err == nil {
			t.Fatal("mixed/missing relay result accepted")
		}
	}
	if _, err := decodeImageBuildFileDraft(append(raw[:len(raw)-1], []byte(",\"HostPath\":\"private\"}")...), q, scope); err == nil {
		t.Fatal("unknown relay field accepted")
	}
}
