// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	oci "github.com/google/go-containerregistry/pkg/registry"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/registryclient"
	bolt "go.etcd.io/bbolt"
)

type publicationFixture struct {
	mu     sync.Mutex
	f      *nativeFixture
	native *NativeJobs
	client *registryclient.Access
	roots  map[string]int
}

// Actual original output files/bbolt + private HTTPS registry/OCI library.
// Current member authority and Docker execution are injected by nativeFixture;
// this does not attest real BuildKit, shared Raft or registry Volume lifetime.
func newPublicationFixture(t *testing.T, mode string, multi bool, tags ...string) (*publicationFixture, *BuiltImage) {
	t.Helper()
	p := &publicationFixture{roots: map[string]int{}}
	backend := oci.New(oci.Logger(log.New(io.Discard, "", 0)))
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		user, password, ok := q.BasicAuth()
		if !ok || user != "builder" || password != "private-native-publish-test" {
			w.Header().Set("WWW-Authenticate", `Basic realm="build"`)
			w.WriteHeader(401)
			return
		}
		p.mu.Lock()
		f, native := p.f, p.native
		p.mu.Unlock()
		if f == nil || native == nil {
			t.Error("registry used before original job")
			w.WriteHeader(500)
			return
		}
		root := q.Method == http.MethodPut && strings.HasPrefix(q.URL.Path, "/v2/"+f.spec.Context.Repository+"/manifests/") && !strings.Contains(strings.TrimPrefix(q.URL.Path, "/v2/"+f.spec.Context.Repository+"/manifests/"), ":")
		if root {
			target := f.spec.RegistryAuthority + "/" + f.spec.Context.Repository + ":" + strings.TrimPrefix(q.URL.Path, "/v2/"+f.spec.Context.Repository+"/manifests/")
			p.mu.Lock()
			p.roots[target]++
			attempt := p.roots[target]
			p.mu.Unlock()
			r, err := native.Record(f.spec)
			found := false
			if err == nil && r.Publication != nil {
				for _, tag := range r.Publication.Tags {
					if tag.Target == target && tag.Started && tag.Sent {
						found = true
					}
				}
			}
			if !found {
				t.Error("root request preceded original durable intent", err)
			}
			if mode == "lost-response" && attempt == 1 {
				// Execute against the actual backend, then drop only its HTTP
				// response. Recovery must read the original content, not repush.
				recorder := httptest.NewRecorder()
				backend.ServeHTTP(recorder, q)
				if recorder.Code != 201 {
					t.Error("fixture root not committed", recorder.Code)
				}
				conn, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				_ = conn.Close()
				return
			}
		}
		if mode == "revoke-before-root" && q.Method == http.MethodPost {
			f.edit(func() { f.grant.Allowed = false; f.grant.Index++ })
		}
		backend.ServeHTTP(w, q)
	}))
	t.Cleanup(server.Close)
	authority := strings.TrimPrefix(server.URL, "https://")
	f := newNativeFixtureWithSpec(t, false, func(spec *JobSpec) {
		spec.RegistryAuthority = authority
		if len(tags) > 0 {
			spec.Context.Tags = append([]string(nil), tags...)
		}
	})
	p.mu.Lock()
	p.f, p.native = f, f.jobs
	p.mu.Unlock()
	_, _, _ = finishOutputTestFixture(t, f, multi)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	var err error
	p.client, err = registryclient.New(authority, []byte("builder"), []byte("private-native-publish-test"), ca)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.client.Close)
	built, err := f.jobs.OpenBuiltImage(f.ctx(), f.spec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = built.Close() })
	return p, built
}

func (p *publicationFixture) count(target string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.roots[target]
}
func (p *publicationFixture) reopen() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.f.reopen()
	p.native = p.f.jobs
}

func TestNativePublicationPersistsOneTagThenObservesLostOriginalBeforeNext(t *testing.T) {
	p, built := newPublicationFixture(t, "lost-response", true, "first", "second")
	f, ctx := p.f, p.f.ctx()
	targets, _ := f.spec.OutputTags()
	if _, err := f.jobs.PublishOutput(ctx, f.spec, built, p.client); !errors.Is(err, reconcile.ErrPending) {
		t.Fatal("lost response hidden", err)
	}
	if p.count(targets[0]) != 1 || p.count(targets[1]) != 0 {
		t.Fatal("unknown root retried or suffix published")
	}
	if err := built.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.jobs.FinishWorkspace(ctx, f.spec); !errors.Is(err, ErrUsed) {
		t.Fatal("unknown publication released workspace", err)
	}
	if _, err := f.jobs.CloseUnsentPublication(f.spec, "CANCELLED"); !errors.Is(err, reconcile.ErrPending) {
		t.Fatal("cancel erased sent unknown", err)
	}
	p.reopen()
	if _, err := f.jobs.RecoverPublication(ctx, f.spec, func(context.Context, string) (registryclient.Resolution, error) {
		return registryclient.Resolution{}, &registryclient.Error{Code: "NOT_FOUND"}
	}); !errors.Is(err, reconcile.ErrPending) {
		t.Fatal("absence treated as non-execution", err)
	}
	other := outputTestImage(t, "arm64")
	raw, err := other.RawManifest()
	if err != nil {
		t.Fatal(err)
	}
	media, err := other.MediaType()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.jobs.RecoverPublication(ctx, f.spec, func(_ context.Context, target string) (registryclient.Resolution, error) {
		return registryclient.ResolveManifest(target, string(media), raw)
	}); !errors.Is(err, reconcile.ErrPending) {
		t.Fatal("other content settled original root", err)
	}
	if _, err := f.jobs.RecoverPublication(ctx, f.spec, p.client.Resolve); !errors.Is(err, reconcile.ErrPending) {
		t.Fatal("unattempted suffix became success", err)
	}
	r, err := f.jobs.Record(f.spec)
	if err != nil || r.Publication.Tags[0].Code != "OK" || r.Publication.Tags[1].Started {
		t.Fatal("original prefix not adopted", r.Publication, err)
	}
	if _, err := f.jobs.PublicationResult(f.spec); !errors.Is(err, reconcile.ErrPending) {
		t.Fatal("partial publication became final", err)
	}
	next, err := f.jobs.OpenBuiltImage(ctx, f.spec)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	// The fixture loses the first response of each tag. It still must never
	// see the acknowledged first tag a second time after process reopening.
	if _, err := f.jobs.PublishOutput(ctx, f.spec, next, p.client); !errors.Is(err, reconcile.ErrPending) {
		t.Fatal("second original lost response", err)
	}
	result, err := f.jobs.RecoverPublication(ctx, f.spec, p.client.Resolve)
	if err != nil || result.Code != "OK" || result.Image != f.spec.OutputRepository()+"@"+built.Metadata.Digest || result.Bytes != built.Metadata.ImageBytes {
		t.Fatal("wrong original publication result", result, err)
	}
	if p.count(targets[0]) != 1 || p.count(targets[1]) != 1 {
		t.Fatal("sent root replayed", p.count(targets[0]), p.count(targets[1]))
	}
	if err := next.Close(); err != nil {
		t.Fatal(err)
	}
	closure, err := f.jobs.FinishWorkspace(ctx, f.spec)
	if err != nil || closure == ([32]byte{}) {
		t.Fatal("could not settle original success", closure, err)
	}
	if got, err := f.jobs.PublicationResult(f.spec); err != nil || got != result {
		t.Fatal("result changed after workspace cleanup", got, err)
	}
}

var errNativePublicationCommit = errors.New("injected original publication completion commit loss")

type publicationCommitFailure struct {
	Transactions
	spec JobSpec
	fail bool
}

func (d *publicationCommitFailure) Update(fn func(*bolt.Tx) error) error {
	return d.Transactions.Update(func(tx *bolt.Tx) error {
		if err := fn(tx); err != nil {
			return err
		}
		var r NativeRecord
		if err := json.Unmarshal(tx.Bucket(nativeBucket).Get(nativeKey(d.spec)), &r); err != nil {
			return err
		}
		if d.fail && r.Publication != nil && r.Publication.Tags[0].Code == "OK" {
			d.fail = false
			return errNativePublicationCommit
		}
		return nil
	})
}

func TestNativePublicationCommitLossOnlyReadsOriginalAcknowledgedTag(t *testing.T) {
	p, built := newPublicationFixture(t, "normal", false)
	f, ctx := p.f, p.f.ctx()
	f.jobs.db = &publicationCommitFailure{Transactions: f.db, spec: f.spec, fail: true}
	if _, err := f.jobs.PublishOutput(ctx, f.spec, built, p.client); !errors.Is(err, errNativePublicationCommit) {
		t.Fatal("completion commit loss hidden", err)
	}
	if err := built.Close(); err != nil {
		t.Fatal(err)
	}
	p.reopen()
	r, err := f.jobs.Record(f.spec)
	if err != nil || !r.Publication.Tags[0].Sent || r.Publication.Tags[0].Code != "" {
		t.Fatal("original sent intent lost", r.Publication, err)
	}
	result, err := f.jobs.RecoverPublication(ctx, f.spec, p.client.Resolve)
	if err != nil || result.Code != "OK" {
		t.Fatal(result, err)
	}
	targets, _ := f.spec.OutputTags()
	if p.count(targets[0]) != 1 {
		t.Fatal("committed original was re-pushed")
	}
	if _, err := f.jobs.FinishWorkspace(ctx, f.spec); err != nil {
		t.Fatal(err)
	}
}

func TestNativePublicationCurrentRevocationStopsNextSDKWrite(t *testing.T) {
	p, built := newPublicationFixture(t, "revoke-before-root", false)
	f, ctx := p.f, p.f.ctx()
	result, err := f.jobs.PublishOutput(ctx, f.spec, built, p.client)
	if err != nil || result.Code != "PERMISSION_REVOKED" {
		t.Fatal("current authority ignored", result, err)
	}
	targets, _ := f.spec.OutputTags()
	if p.count(targets[0]) != 0 {
		t.Fatal("root sent after authority revocation")
	}
	if err := built.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.jobs.FinishWorkspace(ctx, f.spec); err != nil {
		t.Fatal("joined pre-root failure cannot settle", err)
	}
}

func TestNativePublicationInterruptedDependencyUploadDoesNotRestartSDK(t *testing.T) {
	p, built := newPublicationFixture(t, "normal", false)
	f, ctx := p.f, p.f.ctx()
	publication, err := newPublication(f.spec, built.Metadata)
	if err != nil {
		t.Fatal(err)
	}
	publication.Tags[0].Started = true // crash after original dependency intent, before root Sent
	r, err := f.jobs.Record(f.spec)
	if err != nil {
		t.Fatal(err)
	}
	r.Publication = &publication
	if err := f.jobs.save(r); err != nil {
		t.Fatal(err)
	}
	if _, err := f.jobs.PublishOutput(ctx, f.spec, built, p.client); !errors.Is(err, reconcile.ErrPending) {
		t.Fatal("original dependency upload replayed", err)
	}
	if err := built.Close(); err != nil {
		t.Fatal(err)
	}
	p.reopen()
	result, err := f.jobs.RecoverPublication(ctx, f.spec, func(context.Context, string) (registryclient.Resolution, error) {
		t.Error("unsent root required registry read")
		return registryclient.Resolution{}, nil
	})
	if err != nil || result.Code != "STORAGE_UNAVAILABLE" {
		t.Fatal(result, err)
	}
	targets, _ := f.spec.OutputTags()
	if p.count(targets[0]) != 0 {
		t.Fatal("interrupted job acquired a replacement root")
	}
	if _, err := f.jobs.FinishWorkspace(ctx, f.spec); err != nil {
		t.Fatal(err)
	}
}

func TestNativePublicationClosedOutputCannotStartSDKOrClaimUserCancellation(t *testing.T) {
	p, built := newPublicationFixture(t, "normal", false)
	f, ctx := p.f, p.f.ctx()
	if err := built.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.jobs.PublishOutput(ctx, f.spec, built, p.client); !errors.Is(err, ErrStorage) {
		t.Fatal("closed lazy output reused", err)
	}
	targets, _ := f.spec.OutputTags()
	if p.count(targets[0]) != 0 {
		t.Fatal("closed output reached registry")
	}
	publication, err := newPublication(f.spec, built.Metadata)
	if err != nil {
		t.Fatal(err)
	}
	publication.Tags[0].Code, publication.Tags[0].At = "CANCELLED", 1
	if err := publication.validate(f.spec); err != nil {
		t.Fatal(err)
	}
	result, closed := publication.result(f.spec)
	if !closed || result.Code == "CANCELLED" || result.Code == "OK" {
		t.Fatal("SDK context cancellation forged shared user cancel", result, closed)
	}
}
