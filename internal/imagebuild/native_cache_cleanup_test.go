// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	controlapi "github.com/moby/buildkit/api/services/control"
	apitypes "github.com/moby/buildkit/api/types"
	bkclient "github.com/moby/buildkit/client"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type cachePruneControlFixture struct {
	controlapi.UnimplementedControlServer
	mu                      sync.Mutex
	rows                    map[string]*controlapi.UsageRecord
	requests                []*controlapi.PruneRequest
	mode                    string
	before                  func(*controlapi.PruneRequest)
	usageCalls, failUsageAt int
}

func (f *cachePruneControlFixture) Info(context.Context, *controlapi.InfoRequest) (*controlapi.InfoResponse, error) {
	return &controlapi.InfoResponse{BuildkitVersion: &apitypes.BuildkitVersion{Package: "github.com/moby/buildkit", Version: "v0.35.1"}}, nil
}

func (f *cachePruneControlFixture) DiskUsage(context.Context, *controlapi.DiskUsageRequest) (*controlapi.DiskUsageResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.usageCalls++
	if f.failUsageAt > 0 && f.usageCalls >= f.failUsageAt {
		return nil, status.Error(codes.Unavailable, "PASSWORD=observation-error-never-persist")
	}
	out := &controlapi.DiskUsageResponse{}
	for _, row := range f.rows {
		out.Record = append(out.Record, row)
	}
	return out, nil
}
func (f *cachePruneControlFixture) Prune(q *controlapi.PruneRequest, stream grpc.ServerStreamingServer[controlapi.UsageRecord]) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, q)
	if f.before != nil {
		f.before(q)
	}
	if q.All || q.KeepDuration != 0 || q.ReservedSpace != 0 || q.MinFreeSpace != 0 || len(q.Filter) == 0 {
		return status.Error(codes.InvalidArgument, "unexpected scope")
	}
	for _, filter := range q.Filter {
		id := strings.TrimSuffix(strings.TrimPrefix(filter, `id=="`), `"`)
		row := f.rows[id]
		if row == nil || row.InUse {
			continue
		}
		if f.mode == "foreign" {
			row = &controlapi.UsageRecord{ID: "foreign", Size: 1}
		}
		if err := stream.Send(row); err != nil {
			return err
		}
		delete(f.rows, id)
		if f.mode == "partial" {
			return status.Error(codes.Unavailable, "PASSWORD=never-persist-raw")
		}
		if f.mode == "foreign" {
			return nil
		}
	}
	return nil
}

func cacheCleanupFixture(t *testing.T) (*nativeFixture, *bkclient.Client, *cachePruneControlFixture) {
	t.Helper()
	f := newNativeFixture(t, false)
	if err := f.jobs.UseSDK(f.ctx(), f.spec); err != nil {
		t.Fatal(err)
	}
	opts, err := f.plan.createOptionsWithTLS(f.spec, true, true)
	if err != nil {
		t.Fatal(err)
	}
	f.edit(func() { f.options = opts })
	f.prepare(f.ctx())
	if err := f.jobs.Start(f.ctx(), f.spec); err != nil {
		t.Fatal(err)
	}
	r, err := f.jobs.Record(f.spec)
	if err != nil {
		t.Fatal(err)
	}
	r.Solve.Sent = true
	r.Solve.Directory = NativeDirectory{Device: 1, Inode: 1, Mode: 0700}
	if err := f.jobs.save(r); err != nil {
		t.Fatal(err)
	}
	f.jobs.solving[f.spec.Digest()] = true // Real solve ownership is isolated here.
	f.jobs.readers[f.spec.Digest()] = 1
	old := timestamppb.New(time.Unix(1, 0))
	fixture := &cachePruneControlFixture{rows: map[string]*controlapi.UsageRecord{
		"old-one": {ID: "old-one", Size: 10, CreatedAt: old, Description: "RUN PASSWORD=hidden"},
		"old-two": {ID: "old-two", Size: 11, CreatedAt: old},
		"busy":    {ID: "busy", Size: 30, CreatedAt: old, InUse: true},
	}}
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	controlapi.RegisterControlServer(server, fixture)
	go server.Serve(listener)
	t.Cleanup(func() { server.Stop(); _ = listener.Close() })
	sdk, err := bkclient.New(context.Background(), "unix:///cleanup-fixture.sock", bkclient.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return listener.DialContext(ctx) }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sdk.Close() })
	return f, sdk, fixture
}

// Real pinned SDK Prune/DiskUsage, stream decoding and native synchronous DB.
// Container/active solve and server effects are injected; no real cache is
// removed here. Full native/owner/user/rollback stays in the RQ6 final batch.
func TestAutomaticCachePruneRecordsOriginalIntentAndUsesReadbackWithoutReplay(t *testing.T) {
	for _, mode := range []string{"ok", "partial", "foreign"} {
		t.Run(mode, func(t *testing.T) {
			f, sdk, fixture := cacheCleanupFixture(t)
			fixture.mode = mode
			fixture.before = func(_ *controlapi.PruneRequest) {
				if err := f.db.View(func(tx *bolt.Tx) error {
					r, found, err := readNativeCacheCleanup(tx, f.plan.Cache, f.spec.Digest())
					if err != nil || !found || len(r.Steps) != 1 || r.Steps[0].Code != "UNKNOWN" || r.Steps[0].SentAt == 0 || r.Steps[0].ReturnedAt != 0 {
						t.Error("RPC preceded original durable intent", r, err)
					}
					return nil
				}); err != nil {
					t.Error(err)
				}
			}
			if err := f.jobs.maintainCache(context.Background(), f.spec, sdk); err != nil {
				t.Fatal(err)
			}
			page, err := f.jobs.ReadCacheUsage(f.spec, 0, [32]byte{})
			if err != nil || page.Cleanup == nil || !page.Cleanup.Valid(f.plan.Cache) {
				t.Fatal(page, err)
			}
			step := page.Cleanup.Steps[0]
			if mode == "ok" {
				if step.Code != "OK" || step.RemovedCount != 2 || step.ReportedBytes != 21 || len(page.Cleanup.Steps) != 2 || page.ReportedBytes != 30 {
					t.Fatal(page)
				}
			} else {
				if step.Code != "UNKNOWN" || step.ReturnedAt == 0 || len(page.Cleanup.Steps) != 1 || mode == "partial" && step.RemovedCount != 1 || mode == "foreign" && step.RemovedCount != 0 {
					t.Fatal(step)
				}
			}
			fixture.mu.Lock()
			calls := len(fixture.requests)
			_, busy := fixture.rows["busy"]
			fixture.mu.Unlock()
			if calls != 1 || !busy {
				t.Fatal("active record removed or cleanup RPC retried", calls, busy)
			}
			f.reopen()
			recovered, err := f.jobs.ReadCacheUsage(f.spec, 0, [32]byte{})
			if err != nil || recovered.Cleanup == nil || recovered.Cleanup.Steps[0] != step {
				t.Fatal("original receipt lost on reopen", recovered, err)
			}
			raw, _ := json.Marshal(recovered)
			if strings.Contains(string(raw), "PASSWORD") || strings.Contains(string(raw), "hidden") {
				t.Fatal("opaque SDK text exposed")
			}
		})
	}
}

func TestAutomaticCachePruneDenialAndOriginalSentFenceDoNotDispatch(t *testing.T) {
	f, sdk, fixture := cacheCleanupFixture(t)
	u, err := f.jobs.sampleCacheUsage(context.Background(), f.spec, sdk)
	if err != nil || u == nil {
		t.Fatal(err)
	}
	selected, err := SelectCacheCleanup(f.spec, *u, "age")
	if err != nil {
		t.Fatal(err)
	}
	f.edit(func() { f.authorityErr = errors.New("quorum unavailable") })
	if complete, err := f.jobs.runCacheCleanup(context.Background(), f.spec, sdk, selected); err != nil || complete {
		t.Fatal(complete, err)
	}
	page, err := f.jobs.ReadCacheUsage(f.spec, 0, [32]byte{})
	if err != nil || page.Cleanup == nil || page.Cleanup.Steps[0].Code != "NOT_AUTHORIZED" || page.Cleanup.Steps[0].SentAt != 0 {
		t.Fatal(page, err)
	}
	f.edit(func() { f.authorityErr = nil })
	if _, err := f.jobs.runCacheCleanup(context.Background(), f.spec, sdk, selected); err == nil {
		t.Fatal("same phase retried after denial")
	}
	fixture.mu.Lock()
	calls := len(fixture.requests)
	fixture.mu.Unlock()
	if calls != 0 {
		t.Fatal("denied/repeated cleanup reached SDK", calls)
	}
}

type cacheCleanupCommitFailure struct {
	Transactions
	job           [32]byte
	finish, fired bool
}

func (d *cacheCleanupCommitFailure) Update(fn func(*bolt.Tx) error) error {
	return d.Transactions.Update(func(tx *bolt.Tx) error {
		if err := fn(tx); err != nil {
			return err
		}
		var row CacheCleanupStatus
		raw := tx.Bucket(nativeBucket).Get(nativeCacheCleanupKey(d.job))
		if raw == nil || json.Unmarshal(raw, &row) != nil || len(row.Steps) == 0 {
			return nil
		}
		step := row.Steps[len(row.Steps)-1]
		if !d.fired && step.SentAt > 0 && (step.ReturnedAt > 0) == d.finish {
			d.fired = true
			return ErrStorage
		}
		return nil
	})
}

func TestCacheCleanupCommitFailureDoesNotDispatchOrReplayLostPositiveResult(t *testing.T) {
	for _, finish := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-send", true: "after-sdk-ack"}[finish], func(t *testing.T) {
			f, sdk, fixture := cacheCleanupFixture(t)
			fault := &cacheCleanupCommitFailure{Transactions: f.db, job: f.spec.Digest(), finish: finish}
			f.jobs.db = fault
			if err := f.jobs.maintainCache(context.Background(), f.spec, sdk); err == nil || !fault.fired {
				t.Fatal("fault not reached", err)
			}
			fixture.mu.Lock()
			calls := len(fixture.requests)
			fixture.mu.Unlock()
			if !finish && calls != 0 || finish && calls != 1 {
				t.Fatal("RPC crossed failed original intent", calls)
			}
			f.reopen()
			if finish {
				page, err := f.jobs.ReadCacheUsage(f.spec, 0, [32]byte{})
				if err != nil || page.Cleanup == nil || page.Cleanup.Steps[0].Code != "UNKNOWN" || page.Cleanup.Steps[0].ReturnedAt != 0 || page.Cleanup.Steps[0].RemovedCount != 0 {
					t.Fatal("lost ACK write fabricated success", page, err)
				}
				f.jobs.solving[f.spec.Digest()] = true // Even a live client cannot resend this phase.
				u, err := f.jobs.sampleCacheUsage(context.Background(), f.spec, sdk)
				if err != nil || u == nil {
					t.Fatal(err)
				}
				selected, err := SelectCacheCleanup(f.spec, *u, "age")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := f.jobs.runCacheCleanup(context.Background(), f.spec, sdk, selected); err == nil {
					t.Fatal("new observation replayed original phase")
				}
				fixture.mu.Lock()
				after := len(fixture.requests)
				fixture.mu.Unlock()
				if after != calls {
					t.Fatal("unknown cleanup automatically retried")
				}
			}
		})
	}
}

func TestCacheCleanupRejectsChangedObservationAndForeignCacheBorrow(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		t.Run(map[bool]string{false: "changed-observation", true: "foreign-borrow"}[foreign], func(t *testing.T) {
			f, sdk, fixture := cacheCleanupFixture(t)
			u, err := f.jobs.sampleCacheUsage(context.Background(), f.spec, sdk)
			if err != nil || u == nil {
				t.Fatal(err)
			}
			selection, err := SelectCacheCleanup(f.spec, *u, "age")
			if err != nil {
				t.Fatal(err)
			}
			if foreign {
				if err := f.db.Update(func(tx *bolt.Tx) error {
					c, err := readNativeCache(tx, f.spec, f.plan)
					if err != nil {
						return err
					}
					c.Owner = [32]byte{99}
					raw, err := json.Marshal(c)
					if err != nil {
						return err
					}
					return tx.Bucket(nativeBucket).Put(nativeCacheKey(f.plan.Cache), raw)
				}); err != nil {
					t.Fatal(err)
				}
			} else {
				fixture.mu.Lock()
				fixture.rows["new"] = &controlapi.UsageRecord{ID: "new", Size: 5}
				fixture.mu.Unlock()
				if _, err := f.jobs.sampleCacheUsage(context.Background(), f.spec, sdk); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.jobs.runCacheCleanup(context.Background(), f.spec, sdk, selection); err == nil {
				t.Fatal("changed original selection/owner accepted")
			}
			fixture.mu.Lock()
			calls := len(fixture.requests)
			fixture.mu.Unlock()
			if calls != 0 {
				t.Fatal("invalid cache scope reached SDK", calls)
			}
		})
	}
}
