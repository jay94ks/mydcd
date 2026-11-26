// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/nodestorage"
	"github.com/jay94ks/mydcd/internal/userauth"
)

// The fake adapters exercise the command's production transfer loop. Shared
// slots, duplicate receipts and consumption use imagebuild.Upload.
// They do not claim transport authentication or native spool verification.
type buildUploadFixture struct {
	t              *testing.T
	options        buildUploadTarget
	scope          imagebuild.UploadScope
	key            ed25519.PrivateKey
	upload         *imagebuild.Upload
	originals      map[string]control.Change
	originalErrors map[string]error
	mutations      []string
	partCalls      map[uint32]int
	expected       []uint64
	snapshots      int
	recorded       bool
	loseACK        bool
	authorized     bool
	seals          int
	body           []byte
}

func newBuildUploadFixture(t *testing.T, parts int) *buildUploadFixture {
	t.Helper()
	body := bytes.Repeat([]byte{37}, parts*imagebuild.PartBytes-7)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{17}, ed25519.SeedSize))
	cluster := [32]byte{9}
	var owner [32]byte
	copy(owner[:], key.Public().(ed25519.PublicKey))
	f := &buildUploadFixture{t: t, key: key, body: body, recorded: true, authorized: true, originals: map[string]control.Change{}, originalErrors: map[string]error{}, partCalls: map[uint32]int{}}
	f.options = buildUploadTarget{Context: "source", Upload: "original", Prefix: "upload-source"}
	f.scope = imagebuild.UploadScope{Schema: 1, Cluster: cluster, Tenant: "tenant-a", Context: f.options.Context, Upload: f.options.Upload, Creator: "alice", Root: nodestorage.Reference{Cluster: cluster, Node: "node-a", Key: owner, ID: "data", Generation: 1, Path: "/srv/mydc"}, ContextRevision: 1, PolicyRevision: 1, Length: int64(len(body)), Digest: sha256.Sum256(body), Dockerfile: "Dockerfile", ExpandedLimit: 1 << 30, ExpiresAt: 1000}
	if err := f.scope.Validate(); err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *buildUploadFixture) receipt(index uint32, data []byte) imagebuild.PartReceipt {
	r := imagebuild.PartReceipt{Schema: 1, Scope: f.scope.Hash(), Index: index, Length: uint32(len(data)), Digest: sha256.Sum256(data)}
	r.Signature = ed25519.Sign(f.key, imagebuild.PartReceiptBytes(r))
	return r
}
func (f *buildUploadFixture) remember(id, action string, expected uint64, payload any) {
	raw, err := json.Marshal(payload)
	if err != nil {
		f.t.Fatal(err)
	}
	f.originals[id] = control.Change{Schema: 1, Action: action, Expected: expected, Payload: raw}
}
func (f *buildUploadFixture) start() {
	u, err := imagebuild.BeginUpload(f.scope, 100)
	if err != nil {
		f.t.Fatal(err)
	}
	f.upload = &u
	f.remember(f.options.Prefix+"-begin", "begin-build-zip-upload", 0, control.ImageBuildUploadBegin{Tenant: f.scope.Tenant, Context: f.scope.Context, Upload: f.scope.Upload, Length: f.scope.Length, Digest: f.scope.Digest, ExpiresAt: f.scope.ExpiresAt})
}
func (f *buildUploadFixture) put(r imagebuild.PartReceipt, expected uint64) error {
	u, err := f.upload.Put(f.scope.Creator, expected, 101, r)
	if err == nil {
		f.upload = &u
	}
	return err
}
func (f *buildUploadFixture) adapters() buildUploadCalls {
	return buildUploadCalls{
		original: func(id, action string, match func(control.Change) bool) (bool, error) {
			c, ok := f.originals[id]
			if !ok {
				return false, nil
			}
			if c.Action != action || !match(c) {
				return true, errors.New("original differs; preserve journal")
			}
			return true, f.originalErrors[id]
		},
		snapshot: func() (control.ImageBuildPage, *control.ImageBuildUploadView, error) {
			f.snapshots++
			p := control.ImageBuildPage{Schema: 1, Tenant: f.scope.Tenant, Part: "uploads", RootRevision: 10, Epoch: 1}
			if f.upload == nil {
				return p, nil, nil
			}
			u := f.upload
			return p, &control.ImageBuildUploadView{Scope: u.Scope, Revision: u.Revision, Received: u.Received, Closed: u.Closed, Version: u.Version}, nil
		},
		mutate: func(id, action string, expected, epoch uint64, payload any) (*state.Result, error) {
			if _, ok := f.originals[id]; ok {
				return nil, errors.New("original replaced")
			}
			if epoch != 1 {
				return nil, errors.New("epoch changed")
			}
			f.mutations = append(f.mutations, action)
			f.remember(id, action, expected, payload)
			switch q := payload.(type) {
			case control.ImageBuildUploadBegin:
				if expected != 0 || q.Length != f.scope.Length || q.Digest != f.scope.Digest {
					return nil, errors.New("begin changed")
				}
				u, err := imagebuild.BeginUpload(f.scope, 100)
				if err != nil {
					return nil, err
				}
				f.upload = &u
			case control.ImageBuildUploadPart:
				if err := f.put(q.Receipt, expected); err != nil {
					return nil, err
				}
			case control.ImageBuildZIPConsume:
				u, err := f.upload.Consume(f.scope.Creator, q.ID, expected, 101, q.Fact)
				if err != nil {
					return nil, err
				}
				f.upload = &u
			default:
				return nil, errors.New("unexpected management action")
			}
			return &state.Result{Code: state.Applied}, nil
		},
		part: func(scope imagebuild.UploadScope, expected uint64, index uint32, data []byte) (control.ImageBuildIOResult, error) {
			f.partCalls[index]++
			f.expected = append(f.expected, expected)
			if !f.authorized {
				return control.ImageBuildIOResult{}, &userauth.Error{Code: "denied"}
			}
			if scope != f.scope || expected != f.upload.Revision {
				return control.ImageBuildIOResult{}, errors.New("scope/CAS changed")
			}
			want := f.body[int(index)*imagebuild.PartBytes : int(index)*imagebuild.PartBytes+scope.PartLength(index)]
			if !bytes.Equal(data, want) {
				return control.ImageBuildIOResult{}, errors.New("part bytes changed")
			}
			r := f.receipt(index, data)
			result := control.ImageBuildIOResult{Schema: 1, Scope: scope.Hash(), Code: "OK", Part: &r}
			if f.recorded {
				if err := f.put(r, expected); err != nil {
					return result, err
				}
				result.Recorded, result.UploadRevision = true, f.upload.Revision
			}
			if f.loseACK {
				f.loseACK = false
				return control.ImageBuildIOResult{}, &userauth.Error{Code: "transport", Phase: mydcp.Unknown}
			}
			return result, nil
		},
		seal: func(scope imagebuild.UploadScope, expected uint64) (control.ImageBuildIOResult, error) {
			f.seals++
			if scope != f.scope || expected != f.upload.Revision || f.upload.Received != scope.Parts() {
				return control.ImageBuildIOResult{}, errors.New("incomplete original")
			}
			r := imagebuild.SealReceipt{Schema: 1, Scope: scope.Hash(), ZIP: scope.Digest, Tree: sha256.Sum256([]byte("inspected-tree")), Entries: 1, ExpandedBytes: 1}
			r.Signature = ed25519.Sign(f.key, imagebuild.SealReceiptBytes(r))
			return control.ImageBuildIOResult{Schema: 1, Scope: scope.Hash(), Code: "OK", Seal: &r}, nil
		},
		unchanged: func() error { return nil },
	}
}
func (f *buildUploadFixture) run(api buildUploadCalls) (map[string]any, error) {
	return transferRegistryBuildUpload(context.Background(), f.options, f.scope.Tenant, f.scope.Creator, bytes.NewReader(f.body), f.scope.Length, f.scope.Digest, api)
}
func assertBuildUploadManagement(t *testing.T, f *buildUploadFixture, want ...string) {
	t.Helper()
	if strings.Join(f.mutations, ",") != strings.Join(want, ",") {
		t.Fatalf("management actions %v, want %v", f.mutations, want)
	}
}

func TestRegistryBuildUploadRecordedBeyondLedger(t *testing.T) {
	f := newBuildUploadFixture(t, 258)
	result, err := f.run(f.adapters())
	if err != nil || result["bytes"] != f.scope.Length || !f.upload.Closed {
		t.Fatal("recorded upload", result, err)
	}
	if len(f.partCalls) != 258 || len(f.originals) != 2 {
		t.Fatal("parts became generic journals", len(f.partCalls), len(f.originals))
	}
	assertBuildUploadManagement(t, f, "begin-build-zip-upload", "upload-build-zip")
	if f.snapshots != 3 {
		t.Fatal("recorded part count multiplied upload reads", f.snapshots)
	}
	for index, expected := range f.expected {
		if expected != uint64(index)+1 {
			t.Fatal("part CAS did not follow prior recorded ACK", index, expected)
		}
	}
	for _, n := range f.partCalls {
		if n != 1 {
			t.Fatal("automatic part retry", n)
		}
	}
	// The identical loop accepts the maximum scope without a ledger-sized part
	// count restriction. No 500 MB allocation or repeated full-file hashing is
	// needed to check its fixed split and generic operation budget.
	maximum := f.scope
	maximum.Length = imagebuild.MaxZIPBytes
	if maximum.Validate() != nil || maximum.Parts() != 20346 || maximum.PartLength(maximum.Parts()-1) != 1280 {
		t.Fatal("500 MB split changed", maximum.Parts(), maximum.PartLength(maximum.Parts()-1))
	}
	if uint64(maximum.Parts()) <= uint64(state.LedgerLimit) || len(f.mutations) != 2 {
		t.Fatal("maximum upload requires per-part management")
	}
}

func TestRegistryBuildUploadACKLossExplicitOriginalResume(t *testing.T) {
	f := newBuildUploadFixture(t, 3)
	f.loseACK = true
	_, err := f.run(f.adapters())
	var remote *userauth.Error
	if !errors.As(err, &remote) || remote.Phase != mydcp.Unknown || f.upload.Received != 1 || f.partCalls[0] != 1 {
		t.Fatal("lost ACK was retried or erased", err)
	}
	begin := append([]byte(nil), f.originals[f.options.Prefix+"-begin"].Payload...)
	if _, err = f.run(f.adapters()); err == nil || f.partCalls[0] != 1 {
		t.Fatal("implicit resume", err)
	}
	originalPrefix := f.options.Prefix
	f.options.Prefix = "new-prefix"
	f.options.Resume = true
	if _, err = f.run(f.adapters()); err == nil || f.partCalls[0] != 1 {
		t.Fatal("new prefix adopted original", err)
	}
	f.options.Prefix = originalPrefix
	beforeReads := f.snapshots
	result, err := f.run(f.adapters())
	if f.snapshots-beforeReads != 2 {
		t.Fatal("explicit resume did not use only fresh initial/final reads", f.snapshots-beforeReads)
	}
	if err != nil || result["bytes"] != f.scope.Length || f.partCalls[0] != 2 || len(f.originals) != 2 || !bytes.Equal(begin, f.originals[originalPrefix+"-begin"].Payload) {
		t.Fatal("original ACK recovery", result, err)
	}
	assertBuildUploadManagement(t, f, "begin-build-zip-upload", "upload-build-zip")
	// A consumed original is a result lookup, never another transfer/consume.
	if _, err = f.run(f.adapters()); err != nil || f.partCalls[0] != 2 || len(f.mutations) != 2 {
		t.Fatal("consumed original replaced", err)
	}
}

func TestRegistryBuildUploadRecordedACKRevisionChain(t *testing.T) {
	f := newBuildUploadFixture(t, 3)
	api := f.adapters()
	part := api.part
	api.part = func(s imagebuild.UploadScope, e uint64, i uint32, b []byte) (control.ImageBuildIOResult, error) {
		result, err := part(s, e, i, b)
		if err == nil && i == 0 {
			// Another slot commits before this ACK is delivered. Use the owner's
			// returned revision rather than assuming Expected+1 or querying again.
			offset := 2 * imagebuild.PartBytes
			if err = f.put(f.receipt(2, f.body[offset:]), f.upload.Revision); err != nil {
				return result, err
			}
			result.UploadRevision = f.upload.Revision
		}
		return result, err
	}
	if _, err := f.run(api); err != nil || f.snapshots != 3 || fmt.Sprint(f.expected) != "[1 3 4]" {
		t.Fatal("owner ACK revision chain", f.expected, f.snapshots, err)
	}
	assertBuildUploadManagement(t, f, "begin-build-zip-upload", "upload-build-zip")
}

func TestRegistryBuildUploadRecordedACKRejectsStaleAndForeign(t *testing.T) {
	for _, name := range []string{"stale", "scope", "owner", "digest", "index"} {
		t.Run(name, func(t *testing.T) {
			f := newBuildUploadFixture(t, 3)
			api := f.adapters()
			part := api.part
			api.part = func(s imagebuild.UploadScope, e uint64, i uint32, b []byte) (control.ImageBuildIOResult, error) {
				r, err := part(s, e, i, b)
				if err != nil {
					return r, err
				}
				if name == "stale" && i == 0 {
					return r, nil
				}
				switch name {
				case "stale":
					r.UploadRevision = e - 1
				case "scope":
					r.Scope[0] ^= 1
				case "owner":
					r.Part.Signature[0] ^= 1
				case "digest":
					r.Part.Digest[0] ^= 1
					r.Part.Signature = ed25519.Sign(f.key, imagebuild.PartReceiptBytes(*r.Part))
				case "index":
					r.Part.Index++
					r.Part.Signature = ed25519.Sign(f.key, imagebuild.PartReceiptBytes(*r.Part))
				}
				return r, err
			}
			_, err := f.run(api)
			wantCalls := 1
			if name == "stale" {
				wantCalls = 2
			}
			if err == nil || f.seals != 0 || len(f.expected) != wantCalls || f.snapshots != 2 {
				t.Fatal("invalid ACK settled/retried/read around", err, f.expected, f.snapshots)
			}
			assertBuildUploadManagement(t, f, "begin-build-zip-upload")
		})
	}
}

func TestRegistryBuildUploadLegacyOriginalAndStageOnly(t *testing.T) {
	t.Run("older-reply", func(t *testing.T) {
		f := newBuildUploadFixture(t, 2)
		f.recorded = false
		if _, err := f.run(f.adapters()); err != nil {
			t.Fatal(err)
		}
		assertBuildUploadManagement(t, f, "begin-build-zip-upload", "put-build-zip-part", "put-build-zip-part", "upload-build-zip")
		if f.snapshots != 5 || fmt.Sprint(f.expected) != "[1 2]" {
			t.Fatal("legacy stage-only cache not refreshed", f.snapshots, f.expected)
		}
	})
	t.Run("full-legacy-budget", func(t *testing.T) {
		f := newBuildUploadFixture(t, 257)
		f.recorded = false
		if _, err := f.run(f.adapters()); err == nil || !strings.Contains(err.Error(), "budget") || len(f.originals) != 1 || f.partCalls[0] != 1 || f.upload.Received != 0 {
			t.Fatal("full legacy silently rotated/replaced", err)
		}
		assertBuildUploadManagement(t, f, "begin-build-zip-upload")
	})
	for _, outcome := range []string{"applied", "resumed", "failed", "unknown", "different-receipt"} {
		t.Run(outcome, func(t *testing.T) {
			f := newBuildUploadFixture(t, 2)
			f.start()
			f.options.Resume = true
			r := f.receipt(0, f.body[:imagebuild.PartBytes])
			id := f.options.Prefix + "-part-00000"
			if outcome == "different-receipt" {
				r.Digest[0] ^= 1
				r.Signature = ed25519.Sign(f.key, imagebuild.PartReceiptBytes(r))
			}
			f.remember(id, "put-build-zip-part", 1, control.ImageBuildUploadPart{Tenant: f.scope.Tenant, Upload: f.scope.Upload, Receipt: r})
			original := append([]byte(nil), f.originals[id].Payload...)
			sentinel := errors.New("original failed result")
			switch outcome {
			case "applied":
				if err := f.put(r, 1); err != nil {
					t.Fatal(err)
				}
			case "failed":
				f.originalErrors[id] = sentinel
			case "unknown":
				f.originalErrors[id] = &userauth.Error{Code: "transport", Phase: mydcp.Unknown}
			}
			api := f.adapters()
			if outcome == "resumed" {
				original := api.original
				api.original = func(selected, action string, match func(control.Change) bool) (bool, error) {
					known, err := original(selected, action, match)
					if selected == id && known && err == nil {
						err = f.put(r, 1)
					}
					return known, err
				}
			}
			_, err := f.run(api)
			if outcome == "applied" || outcome == "resumed" {
				if err != nil || f.partCalls[0] != 0 || f.partCalls[1] != 1 || f.snapshots != 3 || fmt.Sprint(f.expected) != "[2]" {
					t.Fatal("legacy original restaged", err)
				}
			} else if err == nil || len(f.partCalls) != 0 || len(f.mutations) != 0 {
				t.Fatal("failed/unknown original replaced", err)
			}
			if !bytes.Equal(original, f.originals[id].Payload) {
				t.Fatal("legacy original rewritten")
			}
		})
	}
}

func TestRegistryBuildUploadCurrentAuthorityAndFileChange(t *testing.T) {
	t.Run("current-authority", func(t *testing.T) {
		f := newBuildUploadFixture(t, 2)
		f.start()
		f.options.Resume = true
		f.authorized = false
		_, err := f.run(f.adapters())
		var remote *userauth.Error
		if !errors.As(err, &remote) || remote.Code != "denied" || f.seals != 0 || f.upload.Received != 0 || len(f.mutations) != 0 || f.partCalls[0] != 1 {
			t.Fatal("past begin bypassed current authority", err)
		}
	})
	t.Run("revoked-between-parts", func(t *testing.T) {
		f := newBuildUploadFixture(t, 3)
		api := f.adapters()
		part := api.part
		api.part = func(s imagebuild.UploadScope, e uint64, i uint32, b []byte) (control.ImageBuildIOResult, error) {
			result, err := part(s, e, i, b)
			if err == nil {
				f.authorized = false
			}
			return result, err
		}
		_, err := f.run(api)
		var remote *userauth.Error
		if !errors.As(err, &remote) || remote.Code != "denied" || f.upload.Received != 1 || f.seals != 0 || len(f.expected) != 2 || f.snapshots != 2 {
			t.Fatal("cached ACK bypassed current part authority", err, f.expected, f.snapshots)
		}
		assertBuildUploadManagement(t, f, "begin-build-zip-upload")
	})
	for _, kind := range []string{"content", "append", "truncate"} {
		t.Run(kind, func(t *testing.T) {
			f := newBuildUploadFixture(t, 2)
			path := t.TempDir() + "/context.zip"
			if err := os.WriteFile(path, f.body, 0600); err != nil {
				t.Fatal(err)
			}
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			if err := unchangedBuildUploadFile(context.Background(), file, f.scope.Length, f.scope.Digest); err != nil {
				t.Fatal("unchanged control", err)
			}
			api := f.adapters()
			api.unchanged = func() error {
				switch kind {
				case "content":
					changed := append([]byte(nil), f.body...)
					changed[0] ^= 1
					err = os.WriteFile(path, changed, 0600)
				case "append":
					var writer *os.File
					writer, err = os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
					if err == nil {
						_, err = writer.Write([]byte{1})
						_ = writer.Close()
					}
				case "truncate":
					err = os.Truncate(path, f.scope.Length-1)
				}
				if err != nil {
					return err
				}
				return unchangedBuildUploadFile(context.Background(), file, f.scope.Length, f.scope.Digest)
			}
			if _, err = f.run(api); err == nil || f.seals != 0 || f.upload.Closed {
				t.Fatal("changed file sealed/consumed", err)
			}
			assertBuildUploadManagement(t, f, "begin-build-zip-upload")
		})
	}
}

func TestRegistryBuildUploadPartACKContract(t *testing.T) {
	f := newBuildUploadFixture(t, 2)
	receipt := f.receipt(0, f.body[:imagebuild.PartBytes])
	base := control.ImageBuildIOResult{Schema: 1, Scope: f.scope.Hash(), Code: "OK", Part: &receipt, Recorded: true, UploadRevision: 3}
	if !validBuildUploadPartACK(f.scope, 2, 0, receipt.Digest, base) {
		t.Fatal("later revision ACK recovery rejected")
	}
	for _, name := range []string{"unrecorded-revision", "recorded-zero", "behind", "scope", "index", "length", "signature", "seal", "error"} {
		t.Run(name, func(t *testing.T) {
			r := base
			p := receipt
			p.Signature = append([]byte(nil), receipt.Signature...)
			r.Part = &p
			switch name {
			case "unrecorded-revision":
				r.Recorded = false
			case "recorded-zero":
				r.UploadRevision = 0
			case "behind":
				r.UploadRevision = 1
			case "scope":
				r.Scope[0] ^= 1
			case "index":
				p.Index = 1
			case "length":
				p.Length--
			case "signature":
				p.Signature[0] ^= 1
			case "seal":
				r.Seal = &imagebuild.SealReceipt{}
			case "error":
				r.Code = "CONFLICT"
			}
			if validBuildUploadPartACK(f.scope, 2, 0, receipt.Digest, r) {
				t.Fatal("invalid ACK accepted")
			}
		})
	}
	legacy := base
	legacy.Recorded = false
	legacy.UploadRevision = 0
	if !validBuildUploadPartACK(f.scope, 2, 0, receipt.Digest, legacy) {
		t.Fatal("old zero-field reply rejected")
	}
}

func TestRegistryBuildUploadFinalSnapshotAndOriginalCAS(t *testing.T) {
	for _, name := range []string{"revision", "scope", "missing", "closed"} {
		t.Run(name, func(t *testing.T) {
			f := newBuildUploadFixture(t, 2)
			api := f.adapters()
			snapshot := api.snapshot
			api.snapshot = func() (control.ImageBuildPage, *control.ImageBuildUploadView, error) {
				p, u, err := snapshot()
				if f.snapshots == 3 && u != nil {
					switch name {
					case "revision":
						u.Revision++
					case "scope":
						u.Scope.PolicyRevision++
					case "missing":
						u.Received--
					case "closed":
						u.Closed = true
					}
				}
				return p, u, err
			}
			if _, err := f.run(api); err == nil || f.seals != 0 || len(f.partCalls) != 2 || f.snapshots != 3 {
				t.Fatal("final shared upload mismatch sealed", err)
			}
			assertBuildUploadManagement(t, f, "begin-build-zip-upload")
		})
	}
	// A conflict is returned once; no callback retries a new CAS or refreshes
	// state to automatically re-sign the rejected part.
	f := newBuildUploadFixture(t, 2)
	f.start()
	f.options.Resume = true
	api := f.adapters()
	calls := 0
	api.part = func(imagebuild.UploadScope, uint64, uint32, []byte) (control.ImageBuildIOResult, error) {
		calls++
		return control.ImageBuildIOResult{}, fmt.Errorf("original CAS: %w", imagebuild.ErrConflict)
	}
	if _, err := f.run(api); !errors.Is(err, imagebuild.ErrConflict) || calls != 1 || len(f.mutations) != 0 || f.snapshots != 1 {
		t.Fatal("CAS was automatically replaced", err, calls, f.snapshots)
	}
}
