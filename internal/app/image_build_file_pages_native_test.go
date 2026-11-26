// SPDX-License-Identifier: Apache-2.0

//go:build linux

package app

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/imagebuild"
)

// Extends the existing rollback-owned live CLI/User/Raft/native fixture. No
// additional launcher, image build, registry or Docker lifecycle is introduced.
func (f *managedRegistryNative) verifyImageBuildFilePagesNative(t *testing.T, ctx context.Context, r *Runtime, root string, base imagebuild.ContextSpec, p control.Policy, read func() cluster.View, change func(string, string, uint64, any)) {
	t.Helper()
	spec := base.Own()
	spec.ID, spec.Kind, spec.Secrets, spec.Tags = "native-file-pages", "upload", nil, []string{"native-file-pages"}
	change("rq57-context", "put-build-context", 0, control.ImageBuildContextPut{Spec: spec})
	var versions [][32]byte
	var expected []byte
	for number := 1; number <= 3; number++ {
		expected = append([]byte(fmt.Sprintf("{\"version\":%d,\"payload\":\"", number)), bytes.Repeat([]byte("x"), imagebuild.PartBytes+3)...)
		expected = append(expected, []byte("\"}\n")...)
		var archive bytes.Buffer
		writer := zip.NewWriter(&archive)
		for _, entry := range []struct {
			Path string
			Data []byte
		}{{"Dockerfile", []byte("FROM scratch\n")}, {"composer.json", expected}} {
			body, err := writer.Create(entry.Path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = body.Write(entry.Data); err != nil {
				t.Fatal(err)
			}
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		file := filepath.Join(root, fmt.Sprintf("rq57-version-%d.zip", number))
		if err := os.WriteFile(file, archive.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
		var receipt struct {
			Version string `json:"version"`
		}
		prefix := fmt.Sprintf("rq57-upload-%d", number)
		if err := json.Unmarshal(f.cli(nil, "registry", "upload-context", spec.ID, file, "--upload-id", prefix, "--request-id", prefix, "--tenant", "tenant"), &receipt); err != nil {
			t.Fatal(err)
		}
		decoded, err := hex.DecodeString(receipt.Version)
		if err != nil || len(decoded) != 32 {
			t.Fatal("version receipt", err)
		}
		var version [32]byte
		copy(version[:], decoded)
		versions = append(versions, version)
	}
	version := versions[2]
	versionText := hex.EncodeToString(version[:])
	var tree control.ImageBuildContentPage
	if err := json.Unmarshal(f.cli(nil, "registry", "build-tree", versionText, "--tenant", "tenant"), &tree); err != nil {
		t.Fatal(err)
	}
	var entry imagebuild.Entry
	for _, candidate := range tree.Page.Entries {
		if candidate.Path == "composer.json" {
			entry = candidate
		}
	}
	if entry.Path == "" || entry.Digest != sha256.Sum256(expected) {
		t.Fatal("v3 tree digest missing")
	}
	var actual []byte
	var cursor string
	for offset := uint64(0); ; {
		args := []string{"registry", "build-file", versionText, entry.Path, "--tenant", "tenant"}
		if cursor != "" {
			args = append(args, "--after", cursor)
		}
		var page control.ImageBuildContentPage
		if err := json.Unmarshal(f.cli(nil, args...), &page); err != nil || page.Page.File == nil || page.Page.File.Entry != entry || !page.Page.File.Valid(entry.Path, offset) {
			t.Fatal("actual retained file page", page, err)
		}
		actual = append(actual, page.Page.File.Data...)
		if page.Page.File.Next == 0 {
			break
		}
		cursor, offset = page.Next, page.Page.File.Next
	}
	if !bytes.Equal(actual, expected) || sha256.Sum256(actual) != entry.Digest {
		t.Fatal("v3 EOF bytes do not match original tree")
	}
	// The optional SDK/CLI complete reader checks the same EOF digest before
	// reporting success; the destination remains tentative on any failure.
	destination, err := os.OpenFile(filepath.Join(root, "rq57-file-output"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	var downloaded struct {
		Status string
		File   imagebuild.Entry
	}
	if err = json.Unmarshal(f.cli([]*os.File{destination}, "registry", "build-file", versionText, entry.Path, "--output-fd", "3", "--tenant", "tenant"), &downloaded); err != nil || downloaded.Status != "file-read" || downloaded.File != entry {
		t.Fatal("actual complete file download", err)
	}
	if err = destination.Close(); err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(filepath.Join(root, "rq57-file-output"))
	if err != nil || !bytes.Equal(stored, expected) {
		t.Fatal("complete file destination", err)
	}
	for _, args := range [][]string{{"registry", "build-file", versionText, "../secret", "--tenant", "tenant"}, {"registry", "build-file", versionText, entry.Path, "--tenant", "other"}} {
		output, _, err := f.runCLI(nil, args...)
		if err == nil || bytes.Contains(output, expected[:32]) {
			t.Fatal("path/tenant file exposure")
		}
	}
	draftSpec := spec.Own()
	draftSpec.ID, draftSpec.Kind = "native-file-draft", "draft"
	change("rq57-draft-context", "put-build-context", 0, control.ImageBuildContextPut{Spec: draftSpec})
	var plan imagebuild.DraftResponse
	if err = json.Unmarshal(f.cli(nil, "registry", "draft-plan", draftSpec.ID, "--tenant", "tenant"), &plan); err != nil {
		t.Fatal(err)
	}
	preparedEdit := func(id, value string, revision uint64) string {
		t.Helper()
		edit := imagebuild.DraftEdit{ID: id, Kind: "put", Path: entry.Path, Expected: revision, File: &imagebuild.Entry{Path: entry.Path, Bytes: int64(len(value)), Digest: sha256.Sum256([]byte(value))}}
		return imageBuildNativeJSON(t, root, id, struct {
			Scope imagebuild.DraftScope
			Edit  imagebuild.DraftEdit
			Data  []byte
		}{plan.Scope, edit, []byte(value)})
	}
	first := preparedEdit("rq57-draft-first", "old composer file", 1)
	var editResult imagebuild.DraftResponse
	if err = json.Unmarshal(f.cli(nil, "registry", "draft-edit", draftSpec.ID, first, "--tenant", "tenant"), &editResult); err != nil || editResult.Code != "OK" {
		t.Fatal(err)
	}
	draftTree := func() imagebuild.DraftResponse {
		t.Helper()
		var page struct{ Draft imagebuild.DraftResponse }
		if err := json.Unmarshal(f.cli(nil, "registry", "draft-tree", draftSpec.ID, "--tenant", "tenant"), &page); err != nil || page.Draft.Digest == nil {
			t.Fatal(err)
		}
		return page.Draft
	}
	before := draftTree()
	request := struct {
		Scope    imagebuild.DraftScope
		Revision uint64
		Digest   *[32]byte
		Path     string
		Offset   uint32
	}{plan.Scope, before.Revision, before.Digest, entry.Path, 0}
	requestFile := imageBuildNativeJSON(t, root, "rq57-file-read-old", request)
	var content imagebuild.DraftResponse
	if err = json.Unmarshal(f.cli(nil, "registry", "draft-file", draftSpec.ID, requestFile, "--tenant", "tenant"), &content); err != nil || content.Content == nil || string(content.Content.Data) != "old composer file" {
		t.Fatal("original draft file", err)
	}
	second := preparedEdit("rq57-draft-second", "updated composer file", before.Revision)
	f.cli(nil, "registry", "draft-edit", draftSpec.ID, second, "--tenant", "tenant")
	if _, _, err = f.runCLI(nil, "registry", "draft-file", draftSpec.ID, requestFile, "--tenant", "tenant"); err == nil {
		t.Fatal("old draft revision did not conflict")
	}
	after := draftTree()
	request.Revision, request.Digest = after.Revision, after.Digest
	requestFile = imageBuildNativeJSON(t, root, "rq57-file-read-new", request)
	if err = json.Unmarshal(f.cli(nil, "registry", "draft-file", draftSpec.ID, requestFile, "--tenant", "tenant"), &content); err != nil || content.Content == nil || string(content.Content.Data) != "updated composer file" || sha256.Sum256(content.Content.Data) != content.Content.Entry.Digest {
		t.Fatal("fresh draft tree file", err)
	}
	// All fixture artifacts use normal product retirement, preserving original
	// IDs and pins until actual owner closure. The outer fixture owns rollback.
	for i, version := range versions {
		book, err := p.ImageBuilds(read().State)
		if err != nil {
			t.Fatal(err)
		}
		record, ok := book.Version("tenant", version)
		if !ok {
			t.Fatal("original version lost")
		}
		change(fmt.Sprintf("rq57-delete-version-%d", i), "delete-build-version", record.Number, control.ImageBuildVersionSelection{Tenant: "tenant", ID: version})
	}
	for _, id := range []string{spec.ID, draftSpec.ID} {
		book, err := p.ImageBuilds(read().State)
		if err != nil {
			t.Fatal(err)
		}
		context, ok := book.Context("tenant", id)
		if !ok {
			t.Fatal("original context lost")
		}
		change("rq57-delete-"+id, "delete-build-context", context.Revision, control.ImageBuildSelection{Tenant: "tenant", ID: id})
	}
	registryNativeWait(t, ctx, "RQ57 retained reader retirement", func() bool {
		r.imageBuildMu.Lock()
		defer r.imageBuildMu.Unlock()
		return r.imageBuildTree == nil || r.imageBuildTree.scope == ([32]byte{}) || r.imageBuildTree.file == nil
	})
	f.public["BuildContextFilePages"] = map[string]any{"Version": versionText, "File": entry, "DraftOldRevision": before.Revision, "DraftNewRevision": after.Revision, "EOFVerified": true}
	f.save()
}
