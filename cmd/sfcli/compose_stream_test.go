// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/quic-go/quic-go"
)

func TestRealComposeLargeDocumentStreamAndRejectedInputs(t *testing.T) {
	testRealComposeAppBoundary(t, false, false, "stream")
}

func verifyComposeStreamCLI(t *testing.T, ctx context.Context, root string, call func(int, ...string) []byte, c *userauth.Client, session access.Session, peer sfcp.Peer, issuer ed25519.PrivateKey, p control.Policy, view func() state.State) {
	t.Helper()
	doc := appComposeDocument(32)
	if len(doc) > deployment.ArtifactPartBytes {
		t.Fatal("small baseline input", len(doc))
	}
	large := append([]byte("#"+string(bytes.Repeat([]byte{'x'}, deployment.ArtifactMaxBytes/2-len(doc)-2))+"\n"), doc...)
	if len(large) != deployment.ArtifactMaxBytes/2 {
		t.Fatal("large input with room for the encoded plan")
	}
	path, output := filepath.Join(root, "large.yaml"), filepath.Join(root, "stream-plan.json")
	if err := os.WriteFile(path, large, 0600); err != nil {
		t.Fatal(err)
	}
	before := view().Index()
	p, err := p.Current(view())
	if err != nil {
		t.Fatal(err)
	}
	expected, err := p.AppPlanArtifact(view(), session, session.IssuedAt, "tenant", control.AppPlanRequest{Document: large})
	if err != nil || len(expected) <= 64<<10 {
		t.Fatal("multipart result fixture", len(expected), err)
	}
	call(0, "compose", "plan", "-f", path, "--tenant", "tenant", "--out", output)
	raw, err := os.ReadFile(output)
	info, statErr := os.Stat(output)
	if err != nil || statErr != nil || info.Mode().Perm() != 0600 || !bytes.Equal(bytes.TrimSpace(raw), expected) {
		t.Fatal("complete private stream artifact", err, statErr)
	}
	diff, err := control.DecodeAppDiff(bytes.TrimSpace(call(0, "compose", "diff", "-f", path, "--tenant", "tenant")))
	if err != nil || len(diff.Changes) != 33 || diff.Plan != sha256.Sum256(expected) || diff.InventoryRevision != 0 {
		t.Fatal("large diff", err, len(diff.Changes))
	}
	if view().Index() != before {
		t.Fatal("stream plan/diff created a durable candidate")
	}
	// Both actual authenticated plan paths preserve the planner's symbolic
	// rejection without returning source text or private field values.
	bad := []byte("services:\n  web:\n    private_unknown_field: sensitive-test-value\n")
	_, normalErr := c.PlanApp(ctx, peer, session, "tenant", control.AppPlanRequest{Document: bad})
	_, streamErr := c.StreamAppPlan(ctx, peer, session, "tenant", control.AppPlanRequest{Document: bad})
	for _, err := range []error{normalErr, streamErr} {
		var input *deployment.InputError
		var request *userauth.Error
		if !errors.As(err, &input) || input.Code != "UNSUPPORTED_FIELD" || input.Path != "" || !errors.As(err, &request) || request.Code != "invalid" || request.Phase != sfcp.Completed || bytes.Contains([]byte(err.Error()), []byte("sensitive-test-value")) {
			t.Fatal("planner rejection lost its safe code or completion evidence", err)
		}
	}
	// Source and encoded plan have separate budgets; preserving the original
	// document can make an otherwise bounded source exceed the plan budget.
	maxSource := append([]byte("#"+string(bytes.Repeat([]byte{'x'}, deployment.ArtifactMaxBytes-len(doc)-2))+"\n"), doc...)
	_, budgetErr := c.StreamAppPlan(ctx, peer, session, "tenant", control.AppPlanRequest{Document: maxSource})
	var budgetInput *deployment.InputError
	if !errors.As(budgetErr, &budgetInput) || budgetInput.Code != "PLAN_BUDGET" {
		t.Fatal("encoded plan budget", budgetErr)
	}
	if err := os.WriteFile(path, append(maxSource, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	call(2, "compose", "plan", "-f", path, "--tenant", "tenant")
	if err := os.WriteFile(path, large, 0600); err != nil {
		t.Fatal(err)
	}
	limited := session
	limited.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read}}}
	limited.Signature = ed25519.Sign(issuer, access.SessionBytes(limited))
	if _, err := c.StreamAppPlan(ctx, peer, limited, "tenant", control.AppPlanRequest{Document: large}); err == nil {
		t.Fatal("Read scope accepted streamed Deploy")
	}

	// All malformed input cases use a real authenticated QUIC/User stream and
	// check that the actual daemon rejects before any planning publication.
	input := appComposeDocument(1)
	for _, mode := range []string{"offset", "request", "header", "digest", "truncated", "trailing", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			meta := userauth.AppPlanInput{Length: len(input), Digest: sha256.Sum256(input)}
			if mode == "oversize" {
				meta.Length = deployment.ArtifactMaxBytes + 1
			}
			stream, id, digest, ready := openComposePlanStream(t, ctx, *c, peer, session, meta)
			defer stream.CancelRead(0)
			defer stream.Close()
			if mode == "oversize" {
				if ready.Code != "invalid" {
					t.Fatal(ready.Code)
				}
				return
			}
			if ready.Code != "continue" {
				t.Fatal(ready.Code)
			}
			var offset [8]byte
			data := bytes.Clone(input)
			if mode == "offset" {
				binary.LittleEndian.PutUint64(offset[:], 1)
			}
			if mode == "request" {
				id++
			}
			if mode == "header" {
				digest[0] ^= 1
			}
			if mode == "digest" {
				data[0] ^= 1
			}
			if mode != "truncated" {
				f := sfcp.Frame{Purpose: sfcp.User, Kind: 4, Request: id, Fields: []sfcp.Field{{Tag: 1, Required: true, Value: offset[:]}, {Tag: 2, Required: true, Value: data}, {Tag: 3, Required: true, Value: digest[:]}}}
				_ = sfcp.WriteFrame(stream, f)
				if mode == "trailing" {
					_, _ = stream.Write([]byte{0})
				}
			}
			_ = stream.Close()
			if f, err := sfcp.ReadFrame(stream, 128<<10); err == nil {
				var reply userauth.Reply
				if json.Unmarshal(f.Fields[0].Value, &reply) == nil && reply.Code == "ok" {
					t.Fatal("malformed plan succeeded")
				}
			}
		})
	}
	if view().Index() != before {
		t.Fatal("invalid input mutated Raft or shared uploads")
	}
	// Authorization is checked again after receiving EOF, not frozen at ready.
	stream, id, digest, ready := openComposePlanStream(t, ctx, *c, peer, session, userauth.AppPlanInput{Length: len(input), Digest: sha256.Sum256(input)})
	defer stream.CancelRead(0)
	defer stream.Close()
	if ready.Code != "continue" {
		t.Fatal(ready.Code)
	}
	setNodes := func(id string, nodes []string) {
		t.Helper()
		catalog, err := p.Catalog(view())
		if err != nil {
			t.Fatal(err)
		}
		tenant, _ := catalog.Tenant("tenant")
		raw, err := control.ChangeBytes("set-nodes", session.User, tenant.Revision, control.NodeChangeTo("tenant", tenant.AllowedNodes, nodes))
		if err != nil {
			t.Fatal(err)
		}
		var change control.Change
		_ = json.Unmarshal(raw, &change)
		op, err := c.Prepare(ctx, peer, session, id, change)
		if err != nil {
			t.Fatal(err)
		}
		reply, err := c.Operation(ctx, peer, op, false)
		if err != nil || reply.Result == nil || reply.Result.Code != state.Applied {
			t.Fatal("node assignment", err, reply.Result)
		}
	}
	setNodes("stream-revoke", nil)
	var zero [8]byte
	if err := sfcp.WriteFrame(stream, sfcp.Frame{Purpose: sfcp.User, Kind: 4, Request: id, Fields: []sfcp.Field{{Tag: 1, Required: true, Value: zero[:]}, {Tag: 2, Required: true, Value: input}, {Tag: 3, Required: true, Value: digest[:]}}}); err != nil {
		t.Fatal(err)
	}
	_ = stream.Close()
	final, err := sfcp.ReadFrame(stream, 128<<10)
	var denied userauth.Reply
	if err != nil || json.Unmarshal(final.Fields[0].Value, &denied) != nil || denied.Code != "invalid" {
		t.Fatal("revoked node admission during transfer", err, denied.Code)
	}
	setNodes("stream-restore", []string{"node-a"})
	// This CLI invocation performs over a hundred finite signed Raft calls.
	// Select its existing batch deadline explicitly; retain the full input,
	// default per-call contracts and original upload/operation identities.
	call(0, "--timeout", "45s", "compose", "up", "--operation", "large-up", "--tenant", "tenant", "-f", path)
	apps, err := p.Apps(view())
	if err != nil || len(apps.Records()) != 1 || apps.Records()[0].Operation.ID != "large-up" || apps.Records()[0].Operation.Status != "Planned" {
		t.Fatal("large input up did not use same accepted core", err)
	}
	t.Log("actual CLI/SFCP/auth/Raft/bbolt: exact 2MiB YAML -> original-source-preserving >64KiB plan/private output and diff; encoded plan budget/oversize source/Read/invalid offset/request/header/digest/truncation/trailing reject without shared candidate; post-transfer node revocation denied; restored current policy -> same compose up core with explicit finite CLI batch deadline; native disabled")
}

func openComposePlanStream(t *testing.T, ctx context.Context, c userauth.Client, target sfcp.Peer, session access.Session, meta userauth.AppPlanInput) (*quic.Stream, uint64, [32]byte, userauth.Reply) {
	t.Helper()
	conn, err := c.Mesh.Dial(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	id := c.Mesh.NextRequest()
	body, _ := json.Marshal(userauth.Request{Schema: 1, Method: "app-plan-stream", Tenant: "tenant", AppPlan: &control.AppPlanRequest{}, AppInput: &meta, Nonce: sha256.Sum256([]byte(fmt.Sprint(id)))})
	envelope, _ := json.Marshal(userauth.Envelope{Body: body, Session: &session, Signature: ed25519.Sign(c.Self.Private, access.RequestBytes(session, conn.PeerChallenge(), body))})
	digest := sha256.Sum256(envelope)
	stream, err := conn.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = sfcp.WriteFrame(stream, sfcp.Frame{Purpose: sfcp.User, Kind: 1, Request: id, Fields: []sfcp.Field{{Tag: 1, Required: true, Value: envelope}, {Tag: 2, Required: true, Value: digest[:]}}}); err != nil {
		t.Fatal(err)
	}
	ready, err := sfcp.ReadFrame(stream, 128<<10)
	var reply userauth.Reply
	if err != nil || ready.Request != id || !bytes.Equal(ready.Fields[1].Value, digest[:]) || json.Unmarshal(ready.Fields[0].Value, &reply) != nil {
		t.Fatal("stream header reply", err)
	}
	return stream, id, digest, reply
}
