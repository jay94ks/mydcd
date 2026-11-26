// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/schema"
)

func TestBuildPartPermitEncodingOmitsBodyAndKeepsSealAndLargeSession(t *testing.T) {
	data := bytes.Repeat([]byte("original ZIP part "), imagebuild.PartBytes/18)
	proof := imagebuild.PartProof{Schema: 1, Scope: [32]byte{1}, Length: uint32(len(data)), Digest: sha256.Sum256(data), Expected: 1, Record: true}
	session := access.Session{Schema: 1, ID: "original", User: "uploader"}
	digest := imagebuild.PartSessionDigest(session)
	proof.Session = &digest
	call := control.ImageBuildIOCall{Session: session, Tenant: "tenant", At: 2, Request: imagebuild.Transfer{Upload: "original", Kind: "part", Expected: 1, Data: data, Proof: &proof, Record: true}}
	method, raw, err := imageBuildPermitInput(call)
	part, decodeErr := schema.Decode[control.ImageBuildPartPermitCall](raw)
	if err != nil || decodeErr != nil || method != "image-build-part-permit" || len(raw) > 16<<10 || bytes.Contains(raw, []byte(`"Data"`)) || !reflect.DeepEqual(part.Session, call.Session) || !reflect.DeepEqual(part.Proof, proof) {
		t.Fatal("part permit encoder lost original metadata or kept body", method, len(raw), err, decodeErr)
	}
	// The permitted session syntax can exceed the ordinary fixture's size
	// target. This codec adds no hard 16 KiB rejection or session rewriting.
	large := call
	large.Session.Scopes = nil
	for i := range 256 {
		large.Session.Scopes = append(large.Session.Scopes, access.Scope{Tenant: fmt.Sprintf("tenant-%s-%03d", strings.Repeat("x", 40), i), Actions: []access.Action{access.Read}})
	}
	if !access.ValidateScopes(large.Session.Scopes) {
		t.Fatal("large session codec fixture has invalid scope syntax")
	}
	largeProof := proof
	largeDigest := imagebuild.PartSessionDigest(large.Session)
	largeProof.Session = &largeDigest
	large.Request.Proof = &largeProof
	method, raw, err = imageBuildPermitInput(large)
	part, decodeErr = schema.Decode[control.ImageBuildPartPermitCall](raw)
	if err != nil || decodeErr != nil || method != "image-build-part-permit" || len(raw) <= 16<<10 || !reflect.DeepEqual(part.Session, large.Session) || !reflect.DeepEqual(part.Proof, largeProof) {
		t.Fatal("compact codec imposed a new session cap or changed original proof", len(raw), err, decodeErr)
	}
	seal := call
	seal.Request = imagebuild.Transfer{Upload: "original", Kind: "seal", Expected: 2}
	method, raw, err = imageBuildPermitInput(seal)
	legacy, decodeErr := schema.Decode[control.ImageBuildIOCall](raw)
	if err != nil || decodeErr != nil || method != "image-build-io-permit" || !reflect.DeepEqual(legacy, seal) {
		t.Fatal("seal stopped using the original full permit method", method, err, decodeErr)
	}
	// A metadata request is neither the owner transfer shape nor a valid
	// Transfer. Reject it before any Engine/root/Spool is even available.
	missing := call
	missing.Request.Data = nil
	if _, _, err := imageBuildPermitInput(missing); err == nil {
		t.Fatal("owner permit encoder accepted a part without original bytes")
	}
	owner := Runtime{ctx: context.Background()}
	if _, err := owner.imageBuildTransferOwner(context.Background(), missing); err == nil {
		t.Fatal("metadata part started native owner work")
	}
	compact, err := call.PartPermit()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal(compact)
	if _, err := schema.Decode[control.ImageBuildIOCall](raw); err == nil {
		t.Fatal("compact permit became an owner transfer input")
	}
}

func TestBuildPartMalformedBodyReturnsBeforeHeldNativeGate(t *testing.T) {
	data := []byte("original full part")
	proof := imagebuild.PartProof{Schema: 1, Length: uint32(len(data)), Digest: sha256.Sum256(data), Expected: 1}
	valid := control.ImageBuildIOCall{Tenant: "tenant", Request: imagebuild.Transfer{Upload: "original", Kind: "part", Expected: 1, Data: data, Proof: &proof}}
	for _, mode := range []string{"missing", "digest", "length", "mode"} {
		t.Run(mode, func(t *testing.T) {
			call := valid
			part := proof
			call.Request.Proof = &part
			switch mode {
			case "missing":
				call.Request.Data = nil
			case "digest":
				call.Request.Data = bytes.Repeat([]byte{'x'}, len(data))
			case "length":
				part.Length++
			case "mode":
				call.Request.Record = true
			}
			owner := Runtime{ctx: context.Background()}
			owner.imageBuildMu.Lock()
			defer owner.imageBuildMu.Unlock()
			done := make(chan error, 1)
			go func() { _, err := owner.imageBuildTransferOwner(context.Background(), call); done <- err }()
			select {
			case err := <-done:
				if !errors.Is(err, imagebuild.ErrInvalid) {
					t.Fatal("malformed full transfer did not fail before engine/root admission", err)
				}
			case <-time.After(time.Second):
				t.Fatal("malformed body waited for the native gate")
			}
		})
	}
}

// No Engine or native owners exist. Even the rejection route must consume the
// supplied internal quorum view instead of attempting another currentView RPC.
func TestBuildTransferIngressConsumesSuppliedViewWithoutAnotherBarrier(t *testing.T) {
	owner := Runtime{ctx: context.Background()}
	call := control.ImageBuildIOCall{Tenant: "tenant", Request: imagebuild.Transfer{Upload: "missing", Kind: "seal", Expected: 1}}
	for _, view := range []cluster.View{{Local: true}, {}, {RaftIndex: 1}} {
		out, err := owner.imageBuildTransfer(context.Background(), view, call)
		if err == nil || out.Schema != 0 {
			t.Fatal("missing/uncommitted route produced a native effect")
		}
	}
}
