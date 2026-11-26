// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"errors"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"io"
	"strings"
	"testing"
	"time"
)

func openStream(t *testing.T, c Conn, tenant string, sel ContainerSelection, spec StreamSpec, id string) (Stream, SignedIntent) {
	t.Helper()
	target, err := c.ResolveStream(ctx, tenant, sel, spec)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	intent, err := c.PrepareStream(ctx, target, spec, id)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	s, err := c.OpenStream(ctx, tenant, intent)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return s, intent
}

func recvAll(t *testing.T, s Stream) ([]StreamRecord, error) {
	t.Helper()
	var out []StreamRecord
	for {
		r, err := s.Recv(ctx)
		if err != nil {
			return out, err
		}
		out = append(out, r)
	}
}

func TestStreamLogsFollow(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetStreamTick(0)
	f.SetIdleTimeout(0)
	bob, _ := keyLogin(t, f, "bob", FixtureKey("bob"))
	sel := ContainerSelection{App: "php-shop", Service: "web"}
	s, _ := openStream(t, bob, "shop", sel, LogsFollowSpec(sel, 3, true, true), "")
	first, err := s.Recv(ctx)
	if err != nil || first.Kind != RecordSample || first.Sample.LogDriver != "local" {
		t.Fatalf("first %+v %v", first, err)
	}
	for i := 0; i < 3; i++ {
		r, err := s.Recv(ctx)
		if err != nil || r.Kind != RecordStdout {
			t.Fatalf("tail %d %+v %v", i, r, err)
		}
	}
	f.EmitLog("shop", "php-shop", "web", "stderr", "boom")
	r, err := s.Recv(ctx)
	if err != nil || r.Kind != RecordStderr || !strings.Contains(string(r.Data), "boom") {
		t.Fatalf("emitted %+v %v", r, err)
	}
	f.BreakStreams()
	_, err = s.Recv(ctx)
	wantCode(t, err, CodeClosed)

	// Payments is not readable by bob.
	_, err = bob.ResolveStream(ctx, "payments", ContainerSelection{App: "payments-api", Service: "api"}, LogsFollowSpec(ContainerSelection{App: "payments-api", Service: "api"}, 1, true, false))
	wantCode(t, err, CodeDenied)
	// A viewer cannot exec.
	_, err = bob.ResolveStream(ctx, "shop", sel, ExecStreamSpec([]string{"sh"}, true, true, 24, 80))
	wantCode(t, err, CodeDenied)
}

func TestStreamWatch(t *testing.T) {
	f, _ := newTestFake(t)
	alice := passwordLogin(t, f, "alice", "alice")
	sel := ContainerSelection{App: "php-shop", Service: "db"}
	for _, kind := range []string{"top", "stats"} {
		s, _ := openStream(t, alice, "shop", sel, WatchSpec(kind, sel, time.Second), "")
		r, err := s.Recv(ctx)
		if err != nil || r.Kind != RecordSample || r.Sample.Kind != kind {
			t.Fatalf("%s %+v %v", kind, r, err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestStreamExecInteractiveAndStatus(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	alice := passwordLogin(t, f, "alice", "alice")
	sel := ContainerSelection{App: "php-shop", Service: "web"}
	s, intent := openStream(t, alice, "shop", sel, ExecStreamSpec([]string{"sh"}, true, true, 24, 80), "exec-1")
	r, err := s.Recv(ctx)
	if err != nil || r.Kind != RecordReceipt || r.Receipt.Phase != ExecStarted {
		t.Fatalf("receipt %+v %v", r, err)
	}
	if err := s.Resize(ctx, 30, 100); err != nil {
		t.Fatal(err)
	}
	if err := s.Stdin(ctx, []byte("ls\n")); err != nil {
		t.Fatal(err)
	}
	r, _ = s.Recv(ctx)
	if r.Kind != RecordStdout || string(r.Data) != "ls\n" {
		t.Fatalf("echo %+v", r)
	}

	// Disconnect: the process keeps running.
	f.BreakStreams()
	st, err := alice.ExecStatus(ctx, "shop", intent)
	if err != nil || st.Running == nil || !*st.Running || st.Receipt.Phase != ExecStarted || !st.Receipt.Detached {
		t.Fatalf("status %+v %v", st, err)
	}
	// Opening the same original again does not re-run it.
	again, err := alice.OpenStream(ctx, "shop", intent)
	if err != nil {
		t.Fatal(err)
	}
	recs, err := recvAll(t, again)
	if !errors.Is(err, io.EOF) || len(recs) != 1 || recs[0].Kind != RecordReceipt {
		t.Fatalf("replay %+v %v", recs, err)
	}
}

func TestStreamExecOneShot(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	alice := passwordLogin(t, f, "alice", "alice")
	sel := ContainerSelection{App: "php-shop", Service: "web"}
	s, intent := openStream(t, alice, "shop", sel, ExecStreamSpec([]string{"false"}, false, false, 0, 0), "exec-2")
	recs, err := recvAll(t, s)
	if !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	last := recs[len(recs)-1]
	if last.Kind != RecordReceipt || last.Receipt.Phase != ExecFinished || *last.Receipt.ExitCode != 1 {
		t.Fatalf("records %+v", recs)
	}
	st, err := alice.ExecStatus(ctx, "shop", intent)
	if err != nil || st.Running != nil || *st.Receipt.ExitCode != 1 {
		t.Fatalf("status %+v %v", st, err)
	}
	// Invalid client records are refused locally.
	err = s.Resize(ctx, 1, 1)
	wantCode(t, err, CodeClosed)
}

func TestStreamIntentRules(t *testing.T) {
	f, clk := newTestFake(t)
	f.SetIdleTimeout(0)
	alice := passwordLogin(t, f, "alice", "alice")
	sel := ContainerSelection{App: "php-shop", Service: "web"}
	spec := LogsFollowSpec(sel, 1, true, false)
	target, err := alice.ResolveStream(ctx, "shop", sel, spec)
	if err != nil {
		t.Fatal(err)
	}
	intent, _ := alice.PrepareStream(ctx, target, spec, "")
	clk.add(31 * time.Second)
	_, err = alice.OpenStream(ctx, "shop", intent)
	wantCode(t, err, CodeExpired)

	// Another session cannot open alice's intent.
	other := passwordLogin(t, f, "alice", "alice")
	fresh, _ := alice.PrepareStream(ctx, target, spec, "")
	_, err = other.OpenStream(ctx, "shop", fresh)
	wantCode(t, err, CodeDenied)

	// Target replaced between resolve and open.
	uploadApp(t, alice, "shop", "php-shop", "up-x", []byte(strings.Replace(phpShopYAML, "1.4.2", "1.4.3", 1)))
	apps, _ := alice.Apps(ctx, "shop", "")
	var rev uint64
	for _, a := range apps.Items {
		if a.App == "php-shop" {
			rev = a.Revision
		}
	}
	_, res := submit(t, alice, ActionBeginApp, rev, mustBegin(), rootFor(t, alice, ActionBeginApp))
	if res.Code != ResultApplied {
		t.Fatalf("redeploy %+v", res)
	}
	fresh, _ = alice.PrepareStream(ctx, target, spec, "")
	_, err = alice.OpenStream(ctx, "shop", fresh)
	wantCode(t, err, CodeTargetChanged)
	if id, err := IntentID(fresh); err != nil || !strings.HasPrefix(id, "observe-") {
		t.Fatalf("intent id %q %v", id, err)
	}
}

func mustBegin() control.AppBegin {
	return control.AppBegin{Tenant: "shop", App: "php-shop", Deployment: "dep-php-shop", Upload: "up-x", Operation: "deploy-x"}
}
