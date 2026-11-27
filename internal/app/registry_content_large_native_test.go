// SPDX-License-Identifier: Apache-2.0

//go:build linux

package app

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/registryclient"
)

// This opt-in extension shares the actual native fixture's user session,
// registry Volume, TLS CA, owner and rollback. It streams a real 100 MiB tar
// payload and never treats that as an actual 10 GiB transfer result.
func (f *managedRegistryNative) verifyLargeRegistryContent(t *testing.T, ctx context.Context, root string, p control.Policy, read func() cluster.View) {
	t.Helper()
	const payloadBytes int64 = 100 << 20
	workspace, err := os.MkdirTemp(root, "registry-large-")
	if err != nil {
		t.Fatal(err)
	}
	// Only this newly created fixture directory is removed. Registry data is
	// settled separately through exact upload cancel / management delete + GC.
	defer func() {
		if err := os.RemoveAll(workspace); err != nil {
			t.Error("remove owned large content input/output", err)
		}
	}()
	input, err := os.OpenFile(filepath.Join(workspace, "layer.tar"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	hash := sha256.New()
	w := tar.NewWriter(io.MultiWriter(input, hash))
	if err = w.WriteHeader(&tar.Header{Name: "native-large-" + fmt.Sprint(f.public["Tag"]), Mode: 0444, Size: payloadBytes, Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err = io.CopyN(w, registryNativeZeroReader{}, payloadBytes); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	if err = input.Sync(); err != nil {
		t.Fatal(err)
	}
	stat, err := input.Stat()
	if err != nil || stat.Size() <= payloadBytes || stat.Size() >= 101<<20 {
		t.Fatal("actual large tar input size", err)
	}
	layer := v1.Hash{Algorithm: "sha256", Hex: fmt.Sprintf("%x", hash.Sum(nil))}
	configuration, err := json.Marshal(v1.ConfigFile{Architecture: "amd64", OS: "linux", RootFS: v1.RootFS{Type: "layers", DiffIDs: []v1.Hash{layer}}, Config: v1.Config{Labels: map[string]string{"org.sfc.test.owner": fmt.Sprint(f.public["Tag"]), "org.sfc.test.purpose": "rq6-large-content"}}})
	if err != nil {
		t.Fatal(err)
	}
	config := v1.Hash{Algorithm: "sha256", Hex: fmt.Sprintf("%x", sha256.Sum256(configuration))}
	manifest, err := json.Marshal(v1.Manifest{SchemaVersion: 2, MediaType: types.OCIManifestSchema1, Config: v1.Descriptor{MediaType: types.OCIConfigJSON, Size: int64(len(configuration)), Digest: config}, Layers: []v1.Descriptor{{MediaType: types.OCIUncompressedLayer, Size: stat.Size(), Digest: layer}}})
	if err != nil {
		t.Fatal(err)
	}
	manifestDigest := fmt.Sprintf("sha256:%x", sha256.Sum256(manifest))
	image := f.address + "/fixture@" + manifestDigest
	const deleteID = "rq6-native-large-delete"
	const gcID = "rq6-native-large-gc"
	evidence := map[string]any{"PayloadBytes": payloadBytes, "LayerBytes": stat.Size(), "LayerDigest": layer.String(), "ConfigDigest": config.String(), "ManifestDigest": manifestDigest, "Reference": image, "MaximumContractBytes": registryclient.MaxImageBytes, "ActualTenGiBTransfer": false, "DeleteOperation": deleteID, "GCOperation": gcID, "Cleanup": "prepared"}
	f.public["RegistryRQ6LargeContent"] = evidence
	f.save()
	secret := f.credential(t, "pull,push")
	defer clear(secret)
	token := f.token(t, ctx, secret, "repository:fixture:pull,push")
	activeUpload := ""
	published, unknownUpload, settled := false, false, false
	waitOriginal := func(id string) bool {
		end := time.NewTimer(30 * time.Second)
		defer end.Stop()
		tick := time.NewTicker(50 * time.Millisecond)
		defer tick.Stop()
		for {
			book, err := p.RegistryMaintenanceJobs(read().State)
			if err != nil {
				return false
			}
			if row, ok := book.Record(id); ok && !row.Pending() {
				return row.State == "done" && row.Result != nil && row.Result.Code == "OK" && row.Result.Native != ([32]byte{})
			}
			select {
			case <-ctx.Done():
				return false
			case <-end.C:
				return false
			case <-tick.C:
			}
		}
	}
	missing := func(path string) bool {
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, "https://"+f.address+path, nil)
		if err != nil {
			return false
		}
		req.Header.Set("Authorization", "Bearer "+token)
		response, err := f.http.Do(req)
		if err != nil {
			return false
		}
		_ = response.Body.Close()
		return response.StatusCode == http.StatusNotFound
	}
	// Install rollback before the first registry write. If authority or the
	// original context expires, preserve exact digests/operations and report an
	// incomplete rollback; never claim that an unobserved effect did not occur.
	defer func() {
		if settled {
			return
		}
		evidence["Cleanup"] = "incomplete-original-identities-retained"
		if ctx.Err() == nil && activeUpload != "" {
			req, err := http.NewRequestWithContext(ctx, http.MethodDelete, "https://"+f.address+activeUpload, nil)
			if err == nil {
				req.Header.Set("Authorization", "Bearer "+token)
				response, err := f.http.Do(req)
				if err == nil {
					_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 16<<10))
					_ = response.Body.Close()
					evidence["RollbackUploadStatus"] = response.StatusCode
					if response.StatusCode == http.StatusNoContent {
						activeUpload = ""
					}
				}
			}
		}
		if ctx.Err() == nil {
			if published {
				_, _, err := f.runCLI(nil, "registry", "delete-image", "private", "--tenant", "tenant", "--repository", "fixture", "--reference", manifestDigest, "--expected-digest", manifestDigest, "--request-id", deleteID)
				evidence["RollbackDeleteSubmitted"] = err == nil
				if waitOriginal(deleteID) {
					published = false
					evidence["RollbackDeleteConfirmed"] = true
				}
			}
			// Do not race GC against a pending delete or unresolved upload.
			if !published && !unknownUpload && activeUpload == "" {
				_, _, err := f.runCLI(nil, "registry", "gc", "private", "--tenant", "tenant", "--request-id", gcID)
				evidence["RollbackGCSubmitted"] = err == nil
				if waitOriginal(gcID) && missing("/v2/fixture/blobs/"+layer.String()) && missing("/v2/fixture/blobs/"+config.String()) && missing("/v2/fixture/manifests/"+manifestDigest) {
					evidence["Cleanup"] = "managed-rollback-confirmed"
					settled = true
				}
			}
		}
		f.save()
		if !settled {
			t.Error("large registry path did not finish exact managed cleanup; retain manifest and original registry Volume rollback baseline")
		}
	}()
	upload := func(digest string, length int64, body io.Reader) {
		t.Helper()
		unknownUpload = true
		evidence["UploadAttemptedWithoutLocation"] = true
		f.save()
		headers, _, status := f.request(t, ctx, http.MethodPost, "/v2/fixture/blobs/uploads/", token, nil, nil)
		location := headers.Get("Location")
		parsed, e := url.Parse(location)
		if status != http.StatusAccepted || e != nil || parsed.IsAbs() || parsed.Host != "" || parsed.RawQuery != "" || !strings.HasPrefix(parsed.Path, "/v2/fixture/blobs/uploads/") {
			t.Fatal("exact owned upload location", status)
		}
		activeUpload = location
		unknownUpload = false
		delete(evidence, "UploadAttemptedWithoutLocation")
		evidence["ActiveUpload"] = activeUpload
		f.save()
		query := url.Values{"digest": {digest}}
		req, e := http.NewRequestWithContext(ctx, http.MethodPut, "https://"+f.address+location+"?"+query.Encode(), io.NopCloser(body))
		if e != nil {
			t.Fatal(e)
		}
		req.ContentLength = length
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/octet-stream")
		response, e := f.http.Do(req)
		if e != nil {
			t.Fatal("stream actual large registry blob", e)
		}
		_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 16<<10))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || response.StatusCode != http.StatusCreated || response.Header.Get("Docker-Content-Digest") != digest {
			t.Fatal("original blob publication", response.StatusCode, readErr, closeErr)
		}
		activeUpload = ""
		delete(evidence, "ActiveUpload")
		f.save()
	}
	if _, err = input.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	upload(layer.String(), stat.Size(), input)
	upload(config.String(), int64(len(configuration)), bytes.NewReader(configuration))
	// The digest is the immutable root and the tag exists only in this fixture.
	// Mark attempted before the request so a lost response never means absent.
	published = true
	evidence["ManifestAttempted"] = true
	f.save()
	headers, _, status := f.request(t, ctx, http.MethodPut, "/v2/fixture/manifests/rq6-native-large", token, manifest, map[string]string{"Content-Type": string(types.OCIManifestSchema1)})
	if status != http.StatusCreated || headers.Get("Docker-Content-Digest") != manifestDigest {
		t.Fatal("actual large layer manifest", status)
	}
	output, err := os.OpenFile(filepath.Join(workspace, "content.tar"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	var reply struct {
		Status  string
		Content registryclient.ContentInfo
	}
	if err = json.Unmarshal(f.cli([]*os.File{output}, "--timeout", "3m", "registry", "content", image, "--kind", "layer", "--blob-digest", layer.String(), "--output-fd", "3", "--tenant", "tenant"), &reply); err != nil || reply.Status != "content-read" || !reply.Content.Valid(registryclient.ContentQuery{Ref: image, Kind: "layer", Digest: layer.String()}) || reply.Content.Bytes != stat.Size() || reply.Content.Digest != layer.String() {
		t.Fatal("actual user content stream completion", reply, err)
	}
	if _, err = output.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	actualHash := sha256.New()
	n, err := io.CopyBuffer(actualHash, output, make([]byte, 64<<10))
	var final [1]byte
	endN, endErr := output.Read(final[:])
	if err != nil || n != stat.Size() || fmt.Sprintf("sha256:%x", actualHash.Sum(nil)) != layer.String() || endN != 0 || !errors.Is(endErr, io.EOF) {
		t.Fatal("actual 100 MiB destination length, digest and final EOF", n, err, endN, endErr)
	}
	evidence["ReceivedBytes"], evidence["VerifiedDigest"], evidence["VerifiedEOF"] = n, layer.String(), true
	f.save()
	f.cli(nil, "registry", "delete-image", "private", "--tenant", "tenant", "--repository", "fixture", "--reference", manifestDigest, "--expected-digest", manifestDigest, "--request-id", deleteID)
	deleted := f.maintenanceNativeWait(t, ctx, p, read, deleteID, "done", "OK")
	if deleted.Result.Native == ([32]byte{}) {
		t.Fatal("large manifest delete omitted original native receipt")
	}
	published = false
	f.cli(nil, "registry", "gc", "private", "--tenant", "tenant", "--request-id", gcID)
	collected := f.maintenanceNativeWait(t, ctx, p, read, gcID, "done", "OK")
	if collected.Result.Native == ([32]byte{}) || collected.Result.ReclaimedBytes < stat.Size() {
		t.Fatal("actual large registry bytes not reclaimed", collected)
	}
	// Deletion intentionally waited for the original push lease to expire.
	// That token cannot authenticate the following absence observations. Obtain
	// an explicit CURRENT pull-only grant, which opens no new push lease/fence.
	readSecret := f.credential(t, "pull")
	defer clear(readSecret)
	token = f.token(t, ctx, readSecret, "repository:fixture:pull")
	for _, digest := range []string{layer.String(), config.String()} {
		if _, _, code := f.request(t, ctx, http.MethodHead, "/v2/fixture/blobs/"+digest, token, nil, nil); code == http.StatusUnauthorized || code == http.StatusForbidden {
			t.Fatal("post-GC observation authentication failed", code)
		} else if code != http.StatusNotFound {
			t.Fatal("large fixture blob survived exact managed GC", digest, code)
		}
	}
	if _, _, code := f.request(t, ctx, http.MethodHead, "/v2/fixture/manifests/"+manifestDigest, token, nil, nil); code != http.StatusNotFound {
		t.Fatal("large fixture root survived managed delete", code)
	}
	if _, _, code := f.request(t, ctx, http.MethodHead, "/v2/fixture/manifests/"+strings.SplitN(f.reference, "@", 2)[1], token, nil, nil); code != http.StatusOK {
		t.Fatal("large cleanup changed original app source", code)
	}
	settled = true
	evidence["Cleanup"], evidence["ReclaimedBytes"], evidence["CompletedAt"] = "managed-delete-and-gc-confirmed", collected.Result.ReclaimedBytes, time.Now().UTC().Format(time.RFC3339Nano)
	f.save()
}

type registryNativeZeroReader struct{}

func (registryNativeZeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}
