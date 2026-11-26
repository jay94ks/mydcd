// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"

	"github.com/jay94ks/mydcd/internal/mydcp"
)

// Real authenticated MYDCP/Engine native-observation routing. The callback
// represents owner work; original job/Store authorization is tested separately.
func TestBuildNativeObservationStaysOnOwnerAndRequiresInstalledMember(t *testing.T) {
	for _, method := range []string{"image-build-publication-owner", "image-build-caches-owner", "image-build-cache-owner", "image-build-logs-owner", "image-build-base-owner", "image-build-base-token-owner", "image-build-base-tls-owner", "image-build-registry-tls-owner"} {
		t.Run(method, func(t *testing.T) {

			ownerMethod := method
			var calls atomic.Int32
			f := newControlBoundary(t, func(f *controlBoundary) {
				f.options.ReadModule = func(_ context.Context, method, caller string, input []byte, _ View) (json.RawMessage, error) {
					if method != ownerMethod || caller != f.client.Actor() || string(input) != `{"Tenant":"tenant"}` {
						t.Error("owner callback target changed", method, caller, string(input))
					}
					calls.Add(1)
					return json.RawMessage(`{"Schema":1,"Code":"UNAVAILABLE"}`), nil
				}
			})
			peer, _ := f.lookup(mydcp.Identity(f.node.Public))
			request := ManagementRequest{Method: ownerMethod, Input: []byte(`{"Tenant":"tenant"}`)}
			if reply, err := CallManagement(f.ctx, f.cli, f.client, f.policy.Cluster, peer, request); err == nil && reply.Code == "ok" {
				t.Fatal("non-member accessed owner observation")
			}
			if calls.Load() != 0 {
				t.Fatal("non-member reached native owner")
			}
			f.mu.Lock()
			member := f.peers[mydcp.Identity(f.client.Public)]
			member.Member = true
			f.peers[member.Key] = member
			f.mu.Unlock()
			reply, err := CallManagement(f.ctx, f.cli, f.client, f.policy.Cluster, peer, request)
			if err != nil || reply.Code != "ok" || calls.Load() != 1 {
				t.Fatal("member native route missing", reply, err, calls.Load())
			}
			for _, edit := range []func(*ManagementRequest){func(q *ManagementRequest) { q.Latest = true }, func(q *ManagementRequest) { q.Key = "control/image-builds" }, func(q *ManagementRequest) { q.Command = []byte("not-a-command") }} {
				bad := request
				edit(&bad)
				if reply, err := CallManagement(f.ctx, f.cli, f.client, f.policy.Cluster, peer, bad); err == nil && reply.Code == "ok" {
					t.Fatal("native read accepted leader forwarding/mutation shape", bad)
				}
				if calls.Load() != 1 {
					t.Fatal("invalid native read reached owner")
				}
			}
		})
	}
}
