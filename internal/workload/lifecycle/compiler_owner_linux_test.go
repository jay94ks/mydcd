// SPDX-License-Identifier: Apache-2.0

//go:build linux

package lifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/storage"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

type compilerSDKTransport func(*http.Request) (*http.Response, error)

func (f compilerSDKTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Actual pinned Docker SDK/Wait/receipt persistence with fake HTTP responses.
// Missing input directories and unavailable authority cannot block original
// cleanup. No actual Docker daemon/kernel or successful compilation is claimed.
func TestCheckerCompilerOriginalStopWaitRemoveDoesNotReadSourceOrStartGrant(t *testing.T) {
	_, _, intent, _, private := buildJobFixture(t)
	_, policy := compilationFixture(t)
	base := t.TempDir()
	db, err := storage.Open(filepath.Join(base, "node.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	nativeID := hashText("original-native-sdk")
	c := &engine.Client{Owner: engine.Owner(intent.Cluster, intent.Owner)}
	identity, err := c.Identity("container", compilerKey(intent), reconcile.Resource{Present: true, Generation: 1, Spec: compilerSpec(intent, policy)})
	if err != nil {
		t.Fatal(err)
	}
	running, gone := true, false
	var calls []string
	transport := compilerSDKTransport(func(r *http.Request) (*http.Response, error) {
		name := strings.TrimPrefix(r.URL.Path, "/v1.53")
		calls = append(calls, r.Method+" "+name)
		status := http.StatusOK
		var body any
		switch {
		case r.Method == "GET" && name == "/containers/"+nativeID+"/json":
			if gone {
				status, body = http.StatusNotFound, map[string]string{"message": "No such container"}
			} else {
				body = container.InspectResponse{ID: nativeID, Name: "/" + identity.Name, Config: &container.Config{Labels: identity.Labels}, State: &container.State{Running: running}}
			}
		case r.Method == "POST" && name == "/containers/"+nativeID+"/stop":
			running = false
			status = http.StatusNoContent
		case r.Method == "POST" && name == "/containers/"+nativeID+"/wait":
			body = container.WaitResponse{StatusCode: 0}
		case r.Method == "DELETE" && name == "/containers/"+nativeID:
			gone = true
			status = http.StatusNoContent
		default:
			if r.Method != "GET" {
				t.Fatalf("unexpected native effect %s %s", r.Method, name)
			}
			status, body = http.StatusNotFound, map[string]string{"message": "No such container"}
		}
		data, _ := json.Marshal(body)
		return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(string(data))), Request: r}, nil
	})
	api, err := client.New(client.WithHost("unix:///unused-compiler-test.sock"), client.WithAPIVersion("1.53"), client.WithHTTPClient(&http.Client{Transport: transport}))
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	c.API = api
	owner, err := OpenCompilerOwner(db, filepath.Join(base, "compiler"), intent.Cluster, private, c, func(context.Context, BuildIntent, bool) (CompilerGrant, error) {
		t.Fatal("cleanup requested authority")
		return CompilerGrant{}, ErrCompilerOwner
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	state, _ := reconcile.SetDesired(reconcile.State{}, reconcile.Desired{Revision: 1, Resource: reconcile.Resource{Present: true, Generation: 1, Spec: compilerSpec(intent, policy)}})
	state, _, _ = reconcile.Plan(state)
	state, _ = reconcile.Dispatch(state, state.Pending.ID)
	r := compilerDisk{Schema: 1, Intent: intent, Policy: policy, State: state, Directory: compilerDirectory{1, 2}, InputReady: true, Cancel: true, CreateDispatched: true, ImageID: "sha256:" + hashText("image"), NativeID: nativeID, StartDispatched: true}
	if err := owner.save(r); err != nil {
		t.Fatal(err)
	}
	if err := owner.stopRemoveOriginal(context.Background(), &r); err != nil {
		t.Fatal("original cleanup without source/grant", err)
	}
	got, err := owner.load(intent.Tenant, intent.ID)
	if err != nil || !got.Removed || !got.Exited || got.Closure != nil {
		t.Fatal("native evidence not preserved", err)
	}
	if len(calls) != 5 {
		t.Fatal("Inspect -> Stop -> Wait -> Remove -> Gone", calls)
	}
	// A new fixture's unobserved Create is still Unknown on a name miss.
	unknown := r
	unknown.Intent = intent.Clone()
	unknown.Intent.ID = hashText("unknown-create-sdk")
	unknown.State, _ = reconcile.SetDesired(reconcile.State{}, reconcile.Desired{Revision: 1, Resource: reconcile.Resource{Present: true, Generation: 1, Spec: compilerSpec(unknown.Intent, policy)}})
	unknown.State, _, _ = reconcile.Plan(unknown.State)
	unknown.State, _ = reconcile.Dispatch(unknown.State, unknown.State.Pending.ID)
	unknown.NativeID, unknown.StartDispatched, unknown.Exited, unknown.Removed = "", false, false, false
	if err := owner.save(unknown); err != nil {
		t.Fatal(err)
	}
	if err := owner.stopRemoveOriginal(context.Background(), &unknown); !errors.Is(err, reconcile.ErrPending) || unknown.NativeID != "" || unknown.Removed {
		t.Fatal("name absence treated as closure", err)
	}
}

// Real private DB/lock/filesystem, fake authority. No socket is opened: a
// cancelled job with positive no-Create must settle without any Docker call.
func TestCheckerCompilerOriginalNoCreateClosureAndBorrowedDBRecovery(t *testing.T) {
	_, _, intent, _, private := buildJobFixture(t)
	_, policy := compilationFixture(t)
	base := t.TempDir()
	db, err := storage.Open(filepath.Join(base, "node.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	api, err := client.New(client.WithHost("unix:///nonexistent-mydc-compiler.sock"), client.WithAPIVersion("1.53"))
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	c := &engine.Client{API: api, Owner: engine.Owner(intent.Cluster, intent.Owner)}
	var calls int
	offline := true
	authority := func(_ context.Context, b BuildIntent, recover bool) (CompilerGrant, error) {
		calls++
		if !recover || b.Digest() != intent.Digest() {
			t.Fatal("cancel requested execution authority")
		}
		if offline {
			return CompilerGrant{}, errors.New("quorum unavailable")
		}
		raw, _ := json.Marshal(policy)
		return CompilerGrant{Schema: 1, Job: b.Digest(), Manifest: b.Manifest, Policy: sha256.Sum256(raw), Owner: b.Owner, Phase: "dispatched", Revision: 2, Index: 10, DeadlineUnixMilli: b.DeadlineUnixMilli, Recovery: true}, nil
	}
	path := filepath.Join(base, "compiler")
	owner, err := OpenCompilerOwner(db, path, intent.Cluster, private, c, authority, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { owner.Close() })
	if _, err := OpenCompilerOwner(db, path, intent.Cluster, private, c, authority, nil); err == nil {
		t.Fatal("two namespace owners")
	}
	state, err := reconcile.SetDesired(reconcile.State{}, reconcile.Desired{Revision: 1, Resource: reconcile.Resource{Present: true, Generation: 1, Spec: compilerSpec(intent, policy)}})
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.save(compilerDisk{Schema: 1, Intent: intent, Policy: policy, State: state}); err != nil {
		t.Fatal(err)
	}
	// A cancel must interrupt an admitted Wait even while that Step owns the
	// writer lock; only after it returns can the durable Cancel bit be stored.
	active, stop := context.WithCancel(context.Background())
	owner.active[compilerJobKey(intent)] = stop
	owner.mu.Lock()
	cancelled := make(chan error, 1)
	go func() { cancelled <- owner.Cancel(intent.Tenant, intent.ID) }()
	interrupted := false
	select {
	case <-active.Done():
		interrupted = true
	case <-time.After(2 * time.Second):
	}
	owner.mu.Unlock()
	if err := <-cancelled; err != nil || !interrupted {
		t.Fatal("Cancel blocked behind active SDK writer", err)
	}
	delete(owner.active, compilerJobKey(intent))
	if err := owner.Step(context.Background(), intent.Tenant, intent.ID); !errors.Is(err, reconcile.ErrPending) {
		t.Fatal("offline cleanup inferred a shared closure", err)
	}
	local, err := owner.load(intent.Tenant, intent.ID)
	if err != nil || !local.WorkspaceClosed || !local.CreateNotSent || local.Closure != nil {
		t.Fatal("offline native no-effect cleanup", err)
	}
	offline = false
	if err := owner.Step(context.Background(), intent.Tenant, intent.ID); err != nil {
		t.Fatal("original quorum settlement", err)
	}
	closure, err := owner.Closure(intent.Tenant, intent.ID)
	if err != nil || closure.Verify(intent, "dispatched") != nil || closure.Disposition != "not-created" || closure.Native != "" || calls != 2 {
		t.Fatal("original no-effect proof", err)
	}
	// Immutable closure delivery must not block the common module loop behind
	// an unrelated compiler's long native Wait/writer lock.
	owner.mu.Lock()
	readDone := make(chan error, 1)
	go func() { _, err := owner.Closure(intent.Tenant, intent.ID); readDone <- err }()
	var closureErr error
	readBlocked := false
	select {
	case closureErr = <-readDone:
	case <-time.After(2 * time.Second):
		readBlocked = true
	}
	owner.mu.Unlock()
	if readBlocked {
		<-readDone
		t.Fatal("closure read queued behind native writer")
	}
	if closureErr != nil {
		t.Fatal(closureErr)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Get(compilerPrefix + "identity"); err != nil {
		t.Fatal("owner closed borrowed DB", err)
	}
	owner, err = OpenCompilerOwner(db, path, intent.Cluster, private, c, authority, nil)
	if err != nil {
		t.Fatal("same DB/root recovery", err)
	}
	got, err := owner.Closure(intent.Tenant, intent.ID)
	if err != nil || !reflect.DeepEqual(closure, got) {
		t.Fatal("closure changed", err)
	}
	if err := owner.Step(context.Background(), intent.Tenant, intent.ID); err != nil || calls != 2 {
		t.Fatal("closed original restarted", err)
	}
	jobs, err := owner.Pending()
	if err != nil || len(jobs) != 0 {
		t.Fatal("closed job remained pending", err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+"-original"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenCompilerOwner(db, path, intent.Cluster, private, c, authority, nil); err == nil {
		t.Fatal("same path replaced original directory")
	}
}

func TestCheckerCompilerNativeOptionsAndTamperedContainerRefused(t *testing.T) {
	_, _, intent, _, _ := buildJobFixture(t)
	_, policy := compilationFixture(t)
	r := compilerDisk{Intent: intent, Policy: policy}
	c := &engine.Client{Owner: engine.Owner(intent.Cluster, intent.Owner)}
	identity, err := c.Identity("container", compilerKey(intent), reconcile.Resource{Present: true, Generation: 1, Spec: compilerSpec(intent, policy)})
	if err != nil {
		t.Fatal(err)
	}
	files := &compilerFiles{inputPath: "/owned/input", outputPath: "/owned/output", cachePath: "/owned/cache"}
	options := compilerOptions(r, identity, files)
	got := container.InspectResponse{ID: hashText("native"), Name: "/" + identity.Name, Config: options.Config, HostConfig: options.HostConfig, State: &container.State{}}
	if !matchCompiler(got, r, identity, files) {
		t.Fatal("requested native contract")
	}
	for _, mutate := range []func(*container.InspectResponse){
		func(c *container.InspectResponse) { c.ID = hashText("foreign") },
		func(c *container.InspectResponse) { c.HostConfig.Privileged = true },
		func(c *container.InspectResponse) { c.HostConfig.NetworkMode = "host" },
		func(c *container.InspectResponse) { c.HostConfig.Mounts[0].ReadOnly = false },
		func(c *container.InspectResponse) { c.HostConfig.Mounts[1].Source = "/foreign" },
		func(c *container.InspectResponse) { c.HostConfig.RestartPolicy.Name = "always" },
		func(c *container.InspectResponse) { c.Config.User = "0" },
	} {
		r.NativeID = got.ID
		raw, _ := json.Marshal(got)
		var changed container.InspectResponse
		if json.Unmarshal(raw, &changed) != nil {
			t.Fatal("inspect fixture")
		}
		mutate(&changed)
		if matchCompiler(changed, r, identity, files) {
			t.Fatal("foreign or widened native contract")
		}
	}
}
