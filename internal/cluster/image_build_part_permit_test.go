// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/schema"
)

// CallManagement is the actual signed-envelope/frame encoder and sender. The
// existing Engine fixture authenticates it and enforces its read-only route;
// control package tests separately consume the same DTO in the permit core.
func TestBuildPartPermitManagementMetadataAndReadOnlyAdmission(t *testing.T) {
	body := bytes.Repeat([]byte("owned ZIP body "), imagebuild.UploadPartBytes/15)
	proof := imagebuild.PartProof{Schema: 1, Scope: [32]byte{1}, Length: uint32(len(body)), Digest: sha256.Sum256(body), Expected: 1, Record: true}
	full := control.ImageBuildIOCall{Session: access.Session{Schema: 1, ID: "original-session", User: "uploader"}, Tenant: "tenant", At: 2, Request: imagebuild.Transfer{Upload: "original", Kind: "part", Expected: 1, Data: body, Proof: &proof, Record: true}}
	part, err := full.PartPermit()
	if err != nil {
		t.Fatal(err)
	}
	input, _ := json.Marshal(part)
	var calls atomic.Int32
	f := newControlBoundary(t, func(f *controlBoundary) {
		f.options.ReadModule = func(_ context.Context, method, caller string, input []byte, view View) (json.RawMessage, error) {
			calls.Add(1)
			q, err := schema.Decode[control.ImageBuildPartPermitCall](input)
			if method != "image-build-part-permit" || caller != f.client.Actor() || view.Local || len(input) > 16<<10 || bytes.Contains(input, []byte(`"Data"`)) || bytes.Contains(input, []byte(base64.StdEncoding.EncodeToString(body))) || err != nil || !reflect.DeepEqual(q, part) {
				return nil, errors.New("compact management changed metadata or carried ZIP body")
			}
			return json.RawMessage(`{"Schema":1}`), nil
		}
	})
	peer, _ := f.lookup(mydcp.Identity(f.node.Public))
	request := ManagementRequest{Method: "image-build-part-permit", Latest: true, Input: input}
	if _, err := CallManagement(f.ctx, f.cli, f.client, f.policy.Cluster, peer, request); err == nil || calls.Load() != 0 {
		t.Fatal("non-member reached compact permit core", err)
	}
	f.mu.Lock()
	member := f.peers[mydcp.Identity(f.client.Public)]
	member.Member = true
	f.peers[member.Key] = member
	f.mu.Unlock()
	before, err := f.engine.Read(f.ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if reply, err := CallManagement(f.ctx, f.cli, f.client, f.policy.Cluster, peer, request); err != nil || reply.Code != "ok" || calls.Load() != 1 {
		t.Fatal("actual compact management encoder/route failed", reply.Code, err, calls.Load())
	}
	after, err := f.engine.Read(f.ctx, true)
	if err != nil || after.State.Index() != before.State.Index() || after.State.ReceiptCount() != before.State.ReceiptCount() {
		t.Fatal("compact permit produced a management mutation", err)
	}
	for _, edit := range []func(*ManagementRequest){
		func(q *ManagementRequest) { q.Latest = false },
		func(q *ManagementRequest) { q.Key = "control/image-builds" },
		func(q *ManagementRequest) { q.Command = []byte("not-a-command") },
	} {
		bad := request
		edit(&bad)
		if _, err := CallManagement(f.ctx, f.cli, f.client, f.policy.Cluster, peer, bad); err == nil || calls.Load() != 1 {
			t.Fatal("compact permit admitted a non-quorum or mutation request", err, calls.Load())
		}
	}
	bad := request
	bad.Input = append(append([]byte(nil), input[:len(input)-1]...), []byte(`,"Data":"cmF3"}`)...)
	if _, err := CallManagement(f.ctx, f.cli, f.client, f.policy.Cluster, peer, bad); err == nil || calls.Load() != 2 {
		t.Fatal("compact Management accepted raw data mixed into canonical DTO", err, calls.Load())
	}
}
