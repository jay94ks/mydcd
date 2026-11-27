// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

// The existing fixture has restored and verified this actual inactive native.
// Its non-app move has no automatic Arm/activation producer racing this one
// owner command. Lose knowledge of the reply, not the original intent or CAS.
func verifyMoveOwnerCommitUnobservedReply(t *testing.T, ctx context.Context, root string, client userauth.Client, authority sfcp.Peer, session access.Session, job control.VolumeMove, revision uint64, ready volumes.NativeReady) func() {
	t.Helper()
	if job.App != nil || ready.Verify() != nil || ready.Spec != job.Target || ready.Owner != job.Binding.Target {
		t.Fatal("actual verified non-app target required for stable owner boundary")
	}
	payload := control.VolumeMoveCommit{Selection: job.Selection(), OwnerRevision: job.Binding.SourceOwnerRevision, Target: ready}
	raw, err := control.ChangeBytes("commit-volume-move", session.User, revision, payload)
	if err != nil {
		t.Fatal(err)
	}
	change, err := schema.Decode[control.Change](raw)
	if err != nil {
		t.Fatal(err)
	}
	op, err := client.Prepare(ctx, authority, session, "native-move-owner-commit", change)
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "owner-commit-ack-client")
	if err = os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	record, err := userauth.StageOperation(home, client, op)
	if err != nil || record.Result != nil || !bytes.Equal(control.OperationBytes(record.Operation), control.OperationBytes(op)) || !bytes.Equal(record.Operation.Signature, op.Signature) {
		t.Fatal("owner command was not durably staged before send", err)
	}
	connection, err := client.Mesh.Dial(ctx, authority)
	if err != nil {
		t.Fatal(err)
	}
	request := userauth.Request{Schema: 1, Method: "submit", Operation: &op}
	if _, err = rand.Read(request.Nonce[:]); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(body)
	envelope := userauth.Envelope{Body: body, Session: &session, Signature: ed25519.Sign(client.Self.Private, access.RequestBytes(session, connection.PeerChallenge(), body))}
	wire, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(wire)
	digest := sha256.Sum256(wire)
	id := client.Mesh.NextRequest()
	lifetime, err := sfcp.NewRequest(strconv.FormatUint(id, 10), digest)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := connection.OpenManagement(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.CancelRead(0)
	defer stream.Close()
	lifetime, err = lifetime.BeginSend()
	if err != nil {
		t.Fatal(err)
	}
	frame := sfcp.Frame{Purpose: sfcp.User, Kind: 1, Request: id, Fields: []sfcp.Field{{Tag: 1, Required: true, Value: wire}, {Tag: 2, Required: true, Value: digest[:]}}}
	if err = sfcp.WriteFrame(stream, frame); err != nil {
		t.Fatal("original owner command send", err)
	}
	if err = stream.Close(); err != nil {
		t.Fatal(err)
	}
	// Deliberately never read this stream's response. Keep the server/session
	// alive so a local abandonment cannot masquerade as remote cancellation.
	lifetime = lifetime.Abandon()
	if lifetime.Phase() != sfcp.Unknown || lifetime.SafeToRetry() {
		t.Fatal("sent owner request became safe to resubmit without its result")
	}
	var committed state.Result
	for {
		reply, err := client.Result(ctx, authority, session, op)
		if err != nil {
			t.Fatal("original owner result lookup after unobserved reply", err)
		}
		if reply.Found && reply.Result != nil {
			if reply.Result.Code != state.Applied {
				t.Fatal("original owner command did not commit", reply.Result.Code)
			}
			committed = *reply.Result
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("original owner result remains unknown", ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	// Result/Resume may use fresh authentication, but the staged operation's
	// actor/session/body/signature/ID/CAS remain the original immutable bytes.
	credential, err := identity.LoadPrivateKeyFile(filepath.Join(root, "admin", "key.pem"))
	if err != nil {
		t.Fatal("original account credential required for fresh result login", err)
	}
	current, err := client.Login(ctx, authority, session.User, credential)
	clear(credential)
	if err != nil || current.ID == session.ID {
		t.Fatal("fresh owner result authentication required", err)
	}
	check := func() {
		t.Helper()
		before, err := userauth.LoadOperation(home, client, current, op.RequestID)
		if err != nil || !bytes.Equal(control.OperationBytes(before.Operation), control.OperationBytes(op)) || !bytes.Equal(before.Operation.Signature, op.Signature) {
			t.Fatal("owner result recovery rebound original intent", err)
		}
		for _, resultOnly := range []bool{true, false} {
			var reply userauth.Reply
			if resultOnly {
				reply, err = client.Result(ctx, authority, current, op)
			} else {
				reply, err = client.Resume(ctx, authority, current, op)
			}
			if err != nil || !reply.Found || reply.Result == nil || *reply.Result != committed {
				t.Fatal("owner original result/resume changed committed outcome", err)
			}
		}
		if err = userauth.RecordOperationResult(home, client, current, op, committed); err != nil {
			t.Fatal(err)
		}
		after, err := userauth.LoadOperation(home, client, current, op.RequestID)
		if err != nil || after.Result == nil || *after.Result != committed || !bytes.Equal(control.OperationBytes(after.Operation), control.OperationBytes(op)) {
			t.Fatal("original owner result was not durably retained", err)
		}
	}
	check()
	t.Log("actual inactive native restore/Verified -> durable original user owner command -> authenticated SFCP send with reply deliberately unconsumed/Unknown -> original Applied result -> fresh login/Result/Resume with same actor/session/signature/ID/CAS; no automatic reissue, native Start/Arm or packet-loss claim")
	return check
}
