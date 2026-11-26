// SPDX-License-Identifier: Apache-2.0

//go:build linux

package app

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/imagebuild"
)

type imageBuildZeroReader struct{}

func (imageBuildZeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

// Explicit opt-in within the SAME native scenario. Store ZIP deliberately
// prevents compression from turning a 100MB declaration into a tiny transfer.
// Memory stays bounded; no extra builder, launcher or independent test DB.
func (f *managedRegistryNative) verifyLargeImageBuildZIPNative(t *testing.T, ctx context.Context, root string, base imagebuild.ContextSpec, p control.Policy, read func() cluster.View, change func(string, string, uint64, any)) {
	t.Helper()
	if os.Getenv("MYDC_TEST_RQ6_REMAINING") != "large-context" {
		f.verifyTenantStorageNative(t, ctx, root, base.Root, p, read, change)
	}
	spec := base.Own()
	spec.ID, spec.Secrets, spec.Tags = "native-large", nil, []string{"native-large"}
	change("rq6-large-context", "put-build-context", 0, control.ImageBuildContextPut{Spec: spec})
	file := filepath.Join(root, "original-100mb.zip")
	out, err := os.OpenFile(file, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	writer := zip.NewWriter(out)
	dockerfile := "FROM " + f.reference + "\n"
	df, err := writer.CreateHeader(&zip.FileHeader{Name: "Dockerfile", Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.WriteString(df, dockerfile); err != nil {
		t.Fatal(err)
	}
	body, err := writer.CreateHeader(&zip.FileHeader{Name: "payload.bin", Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	const bodyBytes = 100_000_000
	bodyHash := sha256.New()
	if _, err = io.CopyN(io.MultiWriter(body, bodyHash), imageBuildZeroReader{}, bodyBytes); err != nil {
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err = out.Sync(); err != nil {
		t.Fatal(err)
	}
	info, err := out.Stat()
	if err != nil || info.Size() <= bodyBytes {
		t.Fatal("actual stored ZIP is not over 100MB", err)
	}
	zipHash := sha256.New()
	if _, err = io.Copy(zipHash, io.NewSectionReader(out, 0, info.Size())); err != nil {
		t.Fatal(err)
	}
	if err = out.Close(); err != nil {
		t.Fatal(err)
	}
	args := []string{"--timeout", "5m", "registry", "upload-context", spec.ID, file, "--tenant", "tenant", "--upload-id", "rq6-large-upload", "--request-id", "rq6-large-upload"}
	var result struct {
		Version string `json:"version"`
		Bytes   int64  `json:"bytes"`
	}
	if err = json.Unmarshal(f.cli(nil, args...), &result); err != nil || result.Bytes != info.Size() {
		t.Fatal("actual large CLI upload receipt", err)
	}
	version, err := hex.DecodeString(result.Version)
	if err != nil || len(version) != 32 {
		t.Fatal("large upload version missing", err)
	}
	book, err := p.ImageBuilds(read().State)
	if err != nil {
		t.Fatal(err)
	}
	stored, ok := book.Version("tenant", [32]byte(version))
	if !ok || stored.Fact.ExpandedBytes != bodyBytes+int64(len(dockerfile)) {
		t.Fatal("large native seal expanded length mismatch")
	}
	var upload control.ImageBuildUploadRecord
	for _, candidate := range book.Uploads {
		if candidate.Scope.Tenant == "tenant" && candidate.Scope.Upload == "rq6-large-upload" {
			upload = candidate
		}
	}
	parts := upload.Scope.Parts()
	var consumed control.ImageBuildZIPConsume
	if !upload.Closed || upload.Scope.Length != info.Size() || upload.Scope.Digest != [32]byte(zipHash.Sum(nil)) || upload.Received != 0 || parts != uint32((info.Size()+upload.Scope.PartSize()-1)/upload.Scope.PartSize()) || upload.Origin.Change.Action != "upload-build-zip" || upload.Origin.Change.Expected != uint64(parts)+1 || upload.Revision != uint64(parts)+2 || len(upload.Begin.Change.Payload) > 4096 || len(upload.Origin.Change.Payload) > 4096 || json.Unmarshal(upload.Origin.Change.Payload, &consumed) != nil || consumed.Fact.Scope != upload.Scope.Hash() || !reflect.DeepEqual(consumed.Fact, stored.Fact) {
		t.Fatal("large upload did not use bounded original metadata/parts and final digest")
	}
	// Consume keeps the original signed seal and CAS, while returning live
	// part slots. Received is deliberately zero in every closed upload.
	for _, slot := range read().State.Objects(control.ImageBuildKey + "/slots/tenant/" + upload.Scope.Upload + "/") {
		if slot.Present {
			t.Fatal("consumed large upload retained a live part slot")
		}
	}
	var tree control.ImageBuildContentPage
	if err = json.Unmarshal(f.cli(nil, "registry", "build-tree", result.Version, "--tenant", "tenant"), &tree); err != nil || tree.Next != "" || tree.Page.Version != stored.ID || len(tree.Page.Entries) != 2 || tree.Page.Entries[1].Path != "payload.bin" || tree.Page.Entries[1].Bytes != bodyBytes || tree.Page.Entries[1].Digest != [32]byte(bodyHash.Sum(nil)) {
		t.Fatal("large native tree lost actual file length/digest", err)
	}
	var replay struct {
		Version string `json:"version"`
	}
	if err = json.Unmarshal(f.cli(nil, args...), &replay); err != nil || replay.Version != result.Version {
		t.Fatal("same original large request changed its version", err)
	}
	book, err = p.ImageBuilds(read().State)
	if err != nil {
		t.Fatal(err)
	}
	context, _ := book.Context("tenant", spec.ID)
	replayed, exists := book.Upload("tenant", upload.Scope.Upload)
	if context.NextVersion != stored.Number || !exists || !reflect.DeepEqual(replayed, upload) {
		t.Fatal("original large request changed its upload evidence or published another version")
	}
	change("rq6-large-delete-version", "delete-build-version", stored.Number, control.ImageBuildVersionSelection{Tenant: "tenant", ID: stored.ID})
	change("rq6-large-delete-context", "delete-build-context", context.Revision, control.ImageBuildSelection{Tenant: "tenant", ID: spec.ID})
	registryNativeWait(t, ctx, "original large archive native reclamation", func() bool {
		book, err := p.ImageBuilds(read().State)
		if err != nil {
			t.Fatal(err)
		}
		for _, original := range book.Uploads {
			if original.Scope == upload.Scope && original.Reclaimed != nil {
				return original.Reclaimed.Native != ([32]byte{}) && original.Reclaimed.Version == stored.ID
			}
		}
		return false
	})
	f.public["ImageBuildLargeZIPBytes"], f.public["ImageBuildLargeZIPParts"] = info.Size(), parts
	f.public["ImageBuildLargeZIPVersion"], f.public["ImageBuildLargeZIPReclaimed"] = result.Version, true
	f.save()
}
