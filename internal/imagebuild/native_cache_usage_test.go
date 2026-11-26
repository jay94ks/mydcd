// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"

	controlapi "github.com/moby/buildkit/api/services/control"
	bkclient "github.com/moby/buildkit/client"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type cacheControlFixture struct {
	controlapi.UnimplementedControlServer
	failed atomic.Bool
}

func (f *cacheControlFixture) DiskUsage(context.Context, *controlapi.DiskUsageRequest) (*controlapi.DiskUsageResponse, error) {
	if f.failed.Load() {
		return nil, status.Error(codes.Unavailable, "PASSWORD=opaque-error-never-store")
	}
	return &controlapi.DiskUsageResponse{Record: []*controlapi.UsageRecord{{ID: "actual-sdk-record", Size: 19, Description: "RUN PASSWORD=opaque-description-never-store", RecordType: "regular", InUse: true}}}, nil
}

// Real pinned SDK DiskUsage/gRPC decoding and synchronous native bbolt. The
// daemon response/solve-active fact are fixtures, not a real BuildKit build.
func TestNativeCacheObservationUsesSDKAndRetainsLastSuccessAfterFailureAndReopen(t *testing.T) {
	f := newNativeFixture(t, false)
	if err := f.jobs.UseSDK(f.ctx(), f.spec); err != nil {
		t.Fatal(err)
	}
	options, err := f.plan.createOptionsWithTLS(f.spec, true, true)
	if err != nil {
		t.Fatal(err)
	}
	f.edit(func() { f.options = options })
	f.prepare(f.ctx())
	if err := f.jobs.Start(f.ctx(), f.spec); err != nil {
		t.Fatal(err)
	}
	r, err := f.jobs.Record(f.spec)
	if err != nil {
		t.Fatal(err)
	}
	r.Solve.Sent = true // Isolate observation; real Solve sending has its own gate.
	r.Solve.Directory = NativeDirectory{Device: 1, Inode: 1, Mode: 0700}
	if err := f.jobs.save(r); err != nil {
		t.Fatal(err)
	}
	f.jobs.solving[f.spec.Digest()] = true
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	fixture := &cacheControlFixture{}
	controlapi.RegisterControlServer(server, fixture)
	go server.Serve(listener)
	defer server.Stop()
	defer listener.Close()
	sdk, err := bkclient.New(context.Background(), "unix:///fixture-buildkit.sock", bkclient.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return listener.DialContext(ctx) }))
	if err != nil {
		t.Fatal(err)
	}
	defer sdk.Close()
	if _, err := f.jobs.sampleCacheUsage(context.Background(), f.spec, sdk); err != nil {
		t.Fatal(err)
	}
	first, err := f.jobs.ReadCacheUsage(f.spec, 0, [32]byte{})
	if err != nil || !first.Available || first.ReportedBytes != 19 || !first.Borrowed || first.LastAttemptCode != "OK" {
		t.Fatal(first, err)
	}
	fixture.failed.Store(true)
	if _, err := f.jobs.sampleCacheUsage(context.Background(), f.spec, sdk); err != nil {
		t.Fatal(err)
	}
	f.reopen()
	second, err := f.jobs.ReadCacheUsage(f.spec, 0, first.Snapshot)
	if err != nil || second.Snapshot != first.Snapshot || second.ObservedAt != first.ObservedAt || second.LastAttemptCode != "UNAVAILABLE" || second.ReportedBytes != 19 {
		t.Fatal("failed observation erased/relabelled original", second, err)
	}
	if err := f.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(nativeBucket).Get(cacheUsageKey(f.plan.Cache))
		if strings.Contains(string(raw), "PASSWORD") || strings.Contains(string(raw), "opaque") {
			t.Fatal("opaque SDK data persisted")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Corruption is never repaired into an empty cache measurement.
	if err := f.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(nativeBucket).Put(cacheUsageKey(f.plan.Cache), []byte(`{"Schema":1}`))
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.jobs.ReadCacheUsage(f.spec, 0, [32]byte{}); err == nil {
		t.Fatal("broken observation fabricated empty usage")
	}
}

func TestCacheReadDoesNotCreateNativeJournalAndScopeChangesCannotBorrowAnotherCache(t *testing.T) {
	f := newNativeFixture(t, false)
	other := f.spec.Own()
	other.ID = "never-accepted"
	if _, err := f.jobs.ReadCacheUsage(other, 0, [32]byte{}); err != ErrNativeMissing {
		t.Fatal("missing original was recreated", err)
	}
	original := CacheIdentity(f.spec)
	for _, edit := range []func(*JobSpec){func(s *JobSpec) { s.Context.ID = "other" }, func(s *JobSpec) { s.Tenant = "other" }, func(s *JobSpec) { s.Policy.BuilderImage += "other" }, func(s *JobSpec) { s.Scope.Root.Generation++ }} {
		other = f.spec.Own()
		edit(&other)
		if CacheIdentity(other) == original {
			t.Fatal("foreign cache scope reused")
		}
	}
	other = f.spec.Own()
	other.ID = "new-job"
	if CacheIdentity(other) != original {
		t.Fatal("successive job lost original cache")
	}
}
