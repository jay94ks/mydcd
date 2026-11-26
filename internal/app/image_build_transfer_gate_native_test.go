// SPDX-License-Identifier: Apache-2.0

//go:build linux

package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/userauth"
)

// Reuse the existing registered build root/registry/Runtime in the finite
// transfer-gate scope. One small ordinary-manager upload exercises the real gate,
// current quorum permission, native Spool/RootManager and original ACK. There
// is no additional node, native process, wallet opener or synthetic receipt.
func (f *managedRegistryNative) verifyImageBuildTransferGateNative(t *testing.T, ctx context.Context, r *Runtime, root string, base imagebuild.ContextSpec, p control.Policy, read func() cluster.View, change func(string, string, uint64, any)) {
	t.Helper()
	const username = "rq6-upload-gate-manager"
	key, err := identity.Create(filepath.Join(root, username))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key.Private)
	change("rq6-upload-gate-user", "put-user", 0, access.User{ID: username, Username: username, Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: key.Public, Enabled: true}}})
	change("rq6-upload-gate-member", "set-membership", 0, access.Membership{Tenant: "tenant", User: username, Role: access.Manager, Enabled: true})
	peer := mydcp.Peer{ID: base.Root.Node, Endpoint: r.Mesh.Addr().String(), Policy: mydcp.Policy{Key: mydcp.Identity(r.Identity.Public), Respond: true}}
	mesh, err := mydcp.NewTransport(key, p.Cluster, func(k mydcp.Identity) (mydcp.Peer, bool) { return peer, k == peer.Key })
	if err != nil {
		t.Fatal(err)
	}
	defer mesh.Close()
	client := userauth.Client{Mesh: mesh, Self: key, Cluster: p.Cluster, Peers: []mydcp.Peer{peer}}
	session, err := client.Login(ctx, peer, username, key.Private)
	if err != nil {
		t.Fatal("actual upload gate Manager login", err)
	}
	spec := base.Own()
	spec.ID, spec.Secrets, spec.Tags = "native-upload-gate", nil, []string{"native-upload-gate"}
	submit := func(id, action string, expected uint64, payload any) {
		t.Helper()
		raw, err := control.ChangeBytes(action, username, expected, payload)
		if err != nil {
			t.Fatal(err)
		}
		var ch control.Change
		if err = json.Unmarshal(raw, &ch); err != nil {
			t.Fatal(err)
		}
		op, err := client.Prepare(ctx, peer, session, id, ch)
		if err != nil {
			t.Fatal("original upload gate operation prepare", err)
		}
		reply, err := client.Operation(ctx, peer, op, false)
		if err != nil || reply.Result == nil || reply.Result.Code != state.Applied {
			t.Fatal("original upload gate operation", action, reply.Result, err)
		}
	}
	// The same ordinary Manager defines the context and begins its upload.
	// The accepted begin binds Scope.Creator to this exact session user.
	submit("rq6-upload-gate-context", "put-build-context", 0, control.ImageBuildContextPut{Spec: spec})
	data := bytes.Repeat([]byte("g"), imagebuild.UploadPartBytes)
	whole := append(append([]byte{}, data...), data...)
	const uploadID = "rq6-upload-gate-original"
	submit("rq6-upload-gate-begin", "begin-build-zip-upload", 0, control.ImageBuildUploadBegin{Tenant: "tenant", Context: spec.ID, Upload: uploadID, Length: int64(len(whole)), Digest: sha256.Sum256(whole), ExpiresAt: uint64(time.Now().Add(10 * time.Minute).Unix()), ChunkBytes: imagebuild.UploadPartBytes})
	upload := func() control.ImageBuildUploadRecord {
		t.Helper()
		book, err := p.ImageBuilds(read().State)
		if err != nil {
			t.Fatal(err)
		}
		u, ok := book.Upload("tenant", uploadID)
		if !ok {
			t.Fatal("original gate upload missing")
		}
		return u
	}
	original := upload()
	at := time.Now().Unix()
	sessionDigest := imagebuild.PartSessionDigest(session)
	proof := imagebuild.PartProof{Schema: 1, Scope: original.Scope.Hash(), Length: uint32(len(data)), Digest: sha256.Sum256(data), Expected: original.Revision, At: at, ExpiresAt: min(at+120, session.ExpiresAt), Nonce: [32]byte{79}, Record: true, Session: &sessionDigest}
	proof.Signature = ed25519.Sign(key.Private, imagebuild.PartProofBytes(proof))
	call := control.ImageBuildIOCall{Session: session, Tenant: "tenant", At: at, Request: imagebuild.Transfer{Upload: uploadID, Kind: "part", Expected: original.Revision, Data: data, Proof: &proof, Record: true}}
	before := read()
	if _, err := p.ImageBuildIOPermit(before.State, r.Identity.Public, call); err != nil {
		t.Fatal("current full original upload permission precondition", err)
	}
	roleSequence := 0
	setRole := func(role access.Role) {
		t.Helper()
		catalog, err := p.Catalog(read().State)
		if err != nil {
			t.Fatal(err)
		}
		member, ok := catalog.Membership("tenant", username)
		if !ok {
			t.Fatal("original upload gate membership missing")
		}
		roleSequence++
		change(fmt.Sprintf("rq6-upload-gate-role-%d", roleSequence), "set-membership", member.Revision, access.Membership{Tenant: "tenant", User: username, Role: role, Enabled: true})
	}
	// Freeze the original authorized ingress view while the native gate is
	// held. Authority is withdrawn before release; even a call routed from that
	// valid old view must consume a fresh owner permit after this queued gate.
	r.imageBuildMu.Lock()
	locked, lifeHeld := true, false
	defer func() {
		if locked {
			r.imageBuildMu.Unlock()
		}
		if lifeHeld {
			r.life.RUnlock()
		}
	}()
	type outcome struct {
		result control.ImageBuildIOResult
		err    error
	}
	queued := make(chan outcome, 1)
	started := make(chan struct{})
	go func() {
		close(started)
		result, err := r.imageBuildTransfer(ctx, before, call)
		queued <- outcome{result, err}
	}()
	<-started
	setRole(access.Viewer)
	r.imageBuildMu.Unlock()
	locked = false
	select {
	case out := <-queued:
		if !errors.Is(out.err, mydcp.ErrAdmission) || out.result.Schema != 0 {
			t.Fatal("stale queued ingress view authorized a native effect", out.err)
		}
	case <-ctx.Done():
		t.Fatal("original queued upload response", ctx.Err())
	}
	consumer := buildArtifactConsumer(original.Scope)
	if _, held, err := r.nodeRoots.RecordedPin(original.Scope.Root, consumer); err != nil || held {
		t.Fatal("denied queued call created a native root dependency", err)
	}
	if got := upload(); !reflect.DeepEqual(got, original) {
		t.Fatal("denied queued call changed the original begin/progress")
	}
	setRole(access.Manager)
	work, err := r.imageBuildIOPermit(ctx, call)
	if err != nil {
		t.Fatal("restored original current permission", err)
	}
	// Exercise the SAME native Spool boundary with a current full permit, then
	// withdraw authority after the real stored receipt exists. No production
	// hook stops the owner function between I/O and its final RPC; these are
	// explicit boundary assertions, not a claim about such an injected pause.
	r.life.RLock()
	lifeHeld = true
	r.imageBuildMu.Lock()
	locked = true
	pin, err := r.retainBuildRoot(ctx, original.Scope.Root, work.Root, consumer)
	if err != nil || pin.Directory == nil {
		t.Fatal("original upload root borrow", err)
	}
	directory := pin.Directory
	defer func() {
		if directory != nil {
			_ = directory.Close()
		}
	}()
	spool, err := imagebuild.OpenSpool(pin.Directory.FD(), original.Scope.Root, r.reports)
	if err != nil {
		_ = pin.Directory.Close()
		t.Fatal(err)
	}
	defer spool.Close()
	if err = spool.Begin(ctx, original.Scope); err != nil {
		_ = spool.Close()
		_ = pin.Directory.Close()
		t.Fatal(err)
	}
	receipt, err := spool.Put(ctx, original.Scope, 0, data, r.Identity.Private)
	if err != nil || !receipt.Valid(original.Scope) {
		_ = spool.Close()
		_ = pin.Directory.Close()
		t.Fatal("actual original part durable receipt", err)
	}
	setRole(access.Viewer)
	if _, err := r.imageBuildIOPermit(ctx, call); err == nil {
		t.Fatal("post-I/O current permit reused withdrawn membership")
	}
	recovered, err := spool.RecoverPart(ctx, original.Scope, 0, proof.Digest, r.Identity.Private)
	if err != nil || !reflect.DeepEqual(recovered, receipt) {
		t.Fatal("post-I/O authority refusal discarded original receipt", err)
	}
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}
	if err := directory.Close(); err != nil {
		t.Fatal(err)
	}
	directory = nil
	r.imageBuildMu.Unlock()
	locked = false
	r.life.RUnlock()
	lifeHeld = false
	retained, held, err := r.nodeRoots.RecordedPin(original.Scope.Root, consumer)
	if err != nil || !held || retained.Lease != pin.Lease {
		t.Fatal("post-I/O refusal released/replaced original root lease", err)
	}
	if got := upload(); !reflect.DeepEqual(got, original) {
		t.Fatal("unacknowledged native receipt fabricated shared progress")
	}
	setRole(access.Manager)
	// Resume the unchanged original proof/scope/CAS and same native slot. The
	// owner report confirms it once; subsequent actual SDK ACK recovery must
	// keep that receipt and upload ordinal without per-part user operations.
	out, err := r.imageBuildTransfer(ctx, read(), call)
	if err != nil || !out.Valid(original.Scope, call.Request) || !out.Recorded || out.UploadRevision != original.Revision+1 || out.Part == nil || !reflect.DeepEqual(*out.Part, receipt) {
		t.Fatal("original post-I/O ACK recovery changed its native receipt/CAS", err)
	}
	again, err := client.PutBuildZIPPart(ctx, peer, session, original.Scope, original.Revision, 0, data, true)
	if err != nil || !again.Valid(original.Scope, call.Request) || !again.Recorded || again.UploadRevision != out.UploadRevision || again.Part == nil || !reflect.DeepEqual(*again.Part, receipt) {
		t.Fatal("actual User callback did not recover the same confirmed original slot", err)
	}
	confirmed := upload()
	if confirmed.Revision != original.Revision+1 || confirmed.Received != 1 || !reflect.DeepEqual(confirmed.Begin, original.Begin) || confirmed.Scope != original.Scope {
		t.Fatal("gate recovery replaced original begin/scope or confirmed twice")
	}
	submit("rq6-upload-gate-abort", "abort-build-zip-upload", confirmed.Revision, control.ImageBuildUploadSelection{Tenant: "tenant", Upload: uploadID})
	registryNativeWait(t, ctx, "original upload gate native reclaim", func() bool { return upload().Reclaimed != nil })
	if _, held, err := r.nodeRoots.RecordedPin(original.Scope.Root, consumer); err != nil || held {
		t.Fatal("actual original reclaim retained upload root lease", err)
	}
	book, err := p.ImageBuilds(read().State)
	if err != nil {
		t.Fatal(err)
	}
	context, ok := book.Context("tenant", spec.ID)
	if !ok {
		t.Fatal("original gate context missing")
	}
	submit("rq6-upload-gate-delete-context", "delete-build-context", context.Revision, control.ImageBuildSelection{Tenant: "tenant", ID: spec.ID})
	f.public["ImageBuildTransferGate"] = map[string]any{"OriginalUpload": uploadID, "QueuedCurrentPermissionRefused": true, "PostIOCurrentPermitRefused": true, "OriginalNativeReceiptRecovered": true, "ConfirmedRevision": confirmed.Revision, "NativeReclaimed": true}
	f.save()
}
