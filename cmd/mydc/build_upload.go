// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/userauth"
)

// buildUploadTarget names one ZIP upload: the context, the upload ID and
// the request ID prefix its begin/part/consume originals are saved under.
// Resume continues an upload whose begin was already sent.
type buildUploadTarget struct {
	Context, Upload, Prefix string
	Resume                  bool
}

func buildUploadFileDigest(ctx context.Context, file *os.File, length int64) ([32]byte, error) {
	var digest [32]byte
	hash := sha256.New()
	reader := io.NewSectionReader(file, 0, length)
	buffer := make([]byte, 32<<10)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return digest, err
		}
		n, err := reader.Read(buffer)
		if n > 0 {
			_, _ = hash.Write(buffer[:n])
			total += int64(n)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return digest, err
		}
	}
	if total != length {
		return digest, errors.New("context file changed or truncated")
	}
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}

// Resolve the original journal BEFORE planning another native/data step. A
// missing result is not permission to replace its ID/CAS/receipt/signature.
func resolveBuildUploadOriginal(ctx context.Context, c userauth.Client, target mydcp.Peer, stored userauth.Stored, home, id, action string, resume bool, match func(control.Change) bool) (bool, error) {
	record, err := userauth.LoadOperation(home, c, stored.Session, id)
	if errors.Is(err, userauth.ErrOperationMissing) {
		return false, nil
	}
	if err != nil {
		return true, err
	}
	if record.Operation.Change.Action != action || !match(record.Operation.Change) {
		return true, errors.New("original upload operation differs from selected file/scope; preserve its journal")
	}
	op := record.Operation
	result, err := managementMutation(ctx, c, target, stored, home, id, action, op.Change.Expected, op.Epoch, json.RawMessage(op.Change.Payload), resume)
	if err != nil {
		return true, fmt.Errorf("original upload step %s: %w", id, err)
	}
	if result == nil || result.Code != state.Applied {
		return true, fmt.Errorf("original upload step %s did not apply; preserve its result", id)
	}
	return true, nil
}

// uploadBuildZIP sends the ZIP at path as a new version of the context.
func uploadBuildZIP(ctx context.Context, s *session, tenant, path string, o buildUploadTarget) (map[string]any, error) {
	c, target, stored, home := s.Client, s.Target, s.Stored, s.Home
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open %s", path)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > imagebuild.MaxZIPBytes {
		return nil, errors.New("the context ZIP must be a regular file of at most 500 MB")
	}
	digest, err := buildUploadFileDigest(ctx, file, info.Size())
	if err != nil {
		return nil, err
	}
	api := buildUploadCalls{
		chunkBytes: buildUploadChunkBytes(stored.Session),
		original: func(id, action string, match func(control.Change) bool) (bool, error) {
			return resolveBuildUploadOriginal(ctx, c, target, stored, home, id, action, o.Resume, match)
		},
		snapshot: func() (control.ImageBuildPage, *control.ImageBuildUploadView, error) {
			page, err := c.ImageBuilds(ctx, target, stored.Session, tenant, control.ImageBuildQuery{Part: "uploads", Upload: o.Upload}, "")
			if err != nil || len(page.Uploads) == 0 {
				return page, nil, err
			}
			if len(page.Uploads) != 1 || page.Next != "" {
				return page, nil, errors.New("upload selector returned ambiguous original state")
			}
			return page, &page.Uploads[0], nil
		},
		mutate: func(id, action string, expected, epoch uint64, payload any) (*state.Result, error) {
			return managementMutation(ctx, c, target, stored, home, id, action, expected, epoch, payload, o.Resume)
		},
		part: func(scope imagebuild.UploadScope, expected uint64, index uint32, data []byte) (control.ImageBuildIOResult, error) {
			return c.PutBuildZIPPart(ctx, target, stored.Session, scope, expected, index, data, true)
		},
		seal: func(scope imagebuild.UploadScope, expected uint64) (control.ImageBuildIOResult, error) {
			return c.SealBuildZIP(ctx, target, stored.Session, scope, expected)
		},
		unchanged: func() error { return unchangedBuildUploadFile(ctx, file, info.Size(), digest) },
	}
	return transferRegistryBuildUpload(ctx, o, tenant, stored.Session.User, file, info.Size(), digest, api)
}

// These are the existing CLI adapters, shared by the actual command and its
// failure-injection tests. They create no independent uploader or local store.
type buildUploadCalls struct {
	chunkBytes uint32
	original   func(string, string, func(control.Change) bool) (bool, error)
	snapshot   func() (control.ImageBuildPage, *control.ImageBuildUploadView, error)
	mutate     func(string, string, uint64, uint64, any) (*state.Result, error)
	part       func(imagebuild.UploadScope, uint64, uint32, []byte) (control.ImageBuildIOResult, error)
	seal       func(imagebuild.UploadScope, uint64) (control.ImageBuildIOResult, error)
	unchanged  func() error
}

// Only a new begin chooses the larger wire body. Its original scope fixes the
// size thereafter; a larger session keeps the existing 24 KiB schema-1 path.
func buildUploadChunkBytes(session access.Session) uint32 {
	raw, err := json.Marshal(session)
	if err == nil && len(raw) <= 8<<10 {
		return imagebuild.UploadPartBytes
	}
	return 0
}

func unchangedBuildUploadFile(ctx context.Context, file *os.File, length int64, digest [32]byte) error {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != length {
		return errors.New("original context ZIP changed before sealing")
	}
	current, err := buildUploadFileDigest(ctx, file, length)
	if err != nil || current != digest {
		return errors.New("original context ZIP changed before sealing")
	}
	info, err = file.Stat()
	if err != nil || info.Size() != length {
		return errors.New("original context ZIP changed before sealing")
	}
	return nil
}

func transferRegistryBuildUpload(ctx context.Context, o buildUploadTarget, tenant, creator string, file io.ReaderAt, length int64, digest [32]byte, api buildUploadCalls) (map[string]any, error) {
	prefix := o.Prefix
	beginID := prefix + "-begin"
	var chunkBytes uint32
	beginMatches := func(change control.Change) bool {
		var q control.ImageBuildUploadBegin
		if json.Unmarshal(change.Payload, &q) != nil || q.Tenant != tenant || q.Context != o.Context || q.Upload != o.Upload || q.Length != length || q.Digest != digest {
			return false
		}
		chunkBytes = q.ChunkBytes
		return true
	}
	hadBegin, err := api.original(beginID, "begin-build-zip-upload", beginMatches)
	if err != nil {
		return nil, err
	}
	page, upload, err := api.snapshot()
	if err != nil {
		return nil, err
	}
	if upload == nil {
		if hadBegin {
			return nil, errors.New("original upload is missing; preserve its begin journal without recreating it")
		}
		chunkBytes = api.chunkBytes
		begin := control.ImageBuildUploadBegin{Tenant: tenant, Context: o.Context, Upload: o.Upload, Length: length, Digest: digest, ExpiresAt: uint64(time.Now().Add(time.Hour).Unix()), ChunkBytes: chunkBytes}
		result, err := api.mutate(beginID, "begin-build-zip-upload", 0, page.Epoch, begin)
		if err != nil {
			return nil, err
		}
		if result == nil || result.Code != state.Applied {
			return nil, errors.New("upload begin did not apply; preserve original operation")
		}
		page, upload, err = api.snapshot()
		if err != nil {
			return nil, err
		}
	} else if !hadBegin {
		return nil, errors.New("existing upload requires its original request prefix and begin journal; a new ID cannot adopt it")
	}
	if upload == nil || upload.Scope.Validate() != nil || upload.Scope.Tenant != tenant || upload.Scope.Context != o.Context || upload.Scope.Upload != o.Upload || upload.Scope.Creator != creator || upload.Scope.Length != length || upload.Scope.Digest != digest || upload.Scope.ChunkBytes != chunkBytes || upload.Revision == 0 {
		return nil, errors.New("existing upload does not match original file, context and creator")
	}
	scope := upload.Scope
	consumeID := prefix + "-consume"
	consumeMatches := func(change control.Change) bool {
		var q control.ImageBuildZIPConsume
		return json.Unmarshal(change.Payload, &q) == nil && q.Tenant == tenant && q.ID == o.Context && q.Upload == scope.Upload && q.Fact.Valid(scope)
	}
	if known, err := api.original(consumeID, "upload-build-zip", consumeMatches); err != nil {
		return nil, err
	} else if known {
		_, upload, err = api.snapshot()
		if err != nil {
			return nil, err
		}
	}
	if upload == nil || upload.Scope != scope || upload.Revision == 0 {
		return nil, errors.New("original upload changed after consume result lookup")
	}
	if upload.Closed {
		if upload.Scope != scope || upload.Version == ([32]byte{}) {
			return nil, errors.New("original upload is closed without its matching version; it cannot be reused")
		}
		return map[string]any{"context": o.Context, "upload": scope.Upload, "version": hex.EncodeToString(upload.Version[:]), "state": "consumed", "bytes": scope.Length}, nil
	}
	if hadBegin && !o.Resume {
		return nil, errors.New("original upload is incomplete; preserve its scope and run the same command again with the same --id, or mydc op resume")
	}
	// Recorded is the owner's ACK after current proof/native slot/shared state
	// checks. Chain that committed revision instead of reading the same upload
	// and missing pages again for every part. Legacy edits refresh this cache.
	expected := upload.Revision
	refreshLegacy := func() error {
		page, upload, err = api.snapshot()
		if err != nil {
			return err
		}
		if upload == nil || upload.Closed || upload.Scope != scope || upload.Revision < expected {
			return errors.New("original upload changed after legacy part settlement")
		}
		expected = upload.Revision
		return nil
	}
	buffer := make([]byte, scope.PartSize())
	defer clear(buffer)
	for index := uint32(0); index < scope.Parts(); index++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		data := buffer[:scope.PartLength(index)]
		if n, err := file.ReadAt(data, int64(index)*scope.PartSize()); err != nil || n != len(data) {
			return nil, errors.New("context ZIP changed or cannot be read")
		}
		partDigest := sha256.Sum256(data)
		id := fmt.Sprintf("%s-part-%05d", prefix, index)
		matches := func(change control.Change) bool {
			var q control.ImageBuildUploadPart
			return json.Unmarshal(change.Payload, &q) == nil && q.Tenant == tenant && q.Upload == scope.Upload && q.Receipt.Valid(scope) && q.Receipt.Index == index && q.Receipt.Digest == partDigest
		}
		// Older signed originals always win, including failed/unknown outcomes.
		// Never replace their ID, receipt, CAS, epoch, signature or stored result.
		known, err := api.original(id, "put-build-zip-part", matches)
		if err != nil {
			return nil, err
		}
		if known {
			if err := refreshLegacy(); err != nil {
				return nil, err
			}
			continue
		}
		// Explicit resume deliberately revisits received slots as well as missing
		// ones. Only the owner can recheck native bytes and recover the same ACK.
		native, err := api.part(scope, expected, index, data)
		if err != nil {
			return nil, fmt.Errorf("context part %d outcome unresolved; preserve original upload and use explicit --resume: %w", index, err)
		}
		if !validBuildUploadPartACK(scope, expected, index, partDigest, native) {
			return nil, fmt.Errorf("context part %d returned an invalid original receipt/recorded ACK (%s)", index, native.Code)
		}
		if native.Recorded {
			expected = native.UploadRevision
			continue
		}
		// An older server can only stage. Its original per-part UserOperation
		// remains supported within the unchanged ledger/local journal budget.
		if uint64(scope.Parts())+2 > uint64(state.LedgerLimit) {
			return nil, errors.New("server returned stage-only ZIP parts; this upload cannot fit the original per-part management ledger budget; preserve the upload and original journals, without new IDs or automatic epoch rotation")
		}
		result, err := api.mutate(id, "put-build-zip-part", expected, page.Epoch, control.ImageBuildUploadPart{Tenant: tenant, Upload: scope.Upload, Receipt: *native.Part})
		if err != nil {
			return nil, fmt.Errorf("legacy context part %d did not settle within its original journal/ledger; preserve %s: %w", index, id, err)
		}
		if result == nil || result.Code != state.Applied {
			return nil, fmt.Errorf("legacy part %d CAS did not apply; preserve original %s and its result", index, id)
		}
		if err := refreshLegacy(); err != nil {
			return nil, err
		}
	}
	if err := api.unchanged(); err != nil {
		return nil, err
	}
	page, upload, err = api.snapshot()
	if err != nil {
		return nil, err
	}
	if upload == nil || upload.Closed || upload.Scope != scope || upload.Revision != expected || upload.Received != scope.Parts() {
		return nil, errors.New("original upload is not complete for sealing")
	}
	sealed, err := api.seal(scope, upload.Revision)
	if err != nil {
		return nil, err
	}
	if !sealed.Valid(scope, imagebuild.Transfer{Upload: scope.Upload, Kind: "seal", Expected: upload.Revision}) || sealed.Code != "OK" || sealed.Seal == nil {
		return nil, fmt.Errorf("context seal: %s", sealed.Code)
	}
	result, err := api.mutate(consumeID, "upload-build-zip", upload.Revision, page.Epoch, control.ImageBuildZIPConsume{Tenant: tenant, ID: o.Context, Upload: scope.Upload, Fact: *sealed.Seal})
	if err != nil {
		return nil, err
	}
	if result == nil || result.Code != state.Applied {
		return nil, errors.New("context consume CAS did not apply; preserve original operation")
	}
	version := imagebuild.VersionID(*sealed.Seal)
	return map[string]any{"context": o.Context, "upload": scope.Upload, "version": hex.EncodeToString(version[:]), "bytes": scope.Length}, nil
}

func validBuildUploadPartACK(scope imagebuild.UploadScope, expected uint64, index uint32, digest [32]byte, result control.ImageBuildIOResult) bool {
	if result.Schema != 1 || result.Scope != scope.Hash() || result.Code != "OK" || result.Seal != nil || result.Part == nil || !result.Part.Valid(scope) || result.Part.Index != index || result.Part.Digest != digest {
		return false
	}
	return result.Recorded && result.UploadRevision >= expected && expected > 0 || !result.Recorded && result.UploadRevision == 0
}
