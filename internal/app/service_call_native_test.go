// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/servicecall"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/tests/gitfixture"
)

func TestRQ8ServiceCallHTTPSAndReadOnlyCDProbeNative(t *testing.T) {
	runManagedAppOwner(t, true, true, false, true, managedAppServiceDiagnostics, true)
}

// The existing owned image/network/CLI/Git/runtime and final down/rollback are
// reused. No ready observation, candidate, native ID or source result is forged.
func verifyManagedServiceDiagnostics(t *testing.T, ctx context.Context, r *Runtime, cfg config.Node, root string, user userauth.Client, peer sfcp.Peer, session access.Session, p control.Policy, read func() cluster.View, wait func(string, func() bool), change func(string, string, uint64, any), source *gitfixture.Fixture, original []byte, commit string) *Runtime {
	t.Helper()
	q := servicecall.Request{App: "app", Service: "web", Port: 8080, Path: "/call", Method: "POST", Headers: map[string]string{"Content-Type": "application/octet-stream", "X-SFC-Test": "native"}, Body: bytes.Repeat([]byte("q"), servicecall.MaxBody)}
	want := fmt.Sprintf("%d:%x", len(q.Body), sha256.Sum256(q.Body))
	call := func(c userauth.Client, peer sfcp.Peer, q servicecall.Request, code string) servicecall.Result {
		t.Helper()
		result, err := c.CallService(ctx, peer, session, "tenant", q)
		if err != nil || !result.Valid() || result.Code != code {
			t.Fatal("actual Task service call", q.Scheme, q.Port, q.Path, result, err)
		}
		if code == "" && result.Status == 200 && (string(result.Body) != want || len(result.Headers) != 1 || result.Task == "" || result.Node != cfg.Node.ID) {
			t.Fatal("actual Task response/identity/filter", result)
		}
		return result
	}
	call(user, peer, q, "")
	secure := q
	secure.Scheme = "https"
	secure.Port = 8443
	call(user, peer, secure, "") // The installed tenant CA verifies the actual container IP SAN.
	secure.InsecureSkipVerify = true
	call(user, peer, secure, "")
	secure.Port = 8080
	call(user, peer, secure, servicecall.TLS)
	refused := q
	refused.Port = 1 // The owned fixture exposes only8080 and8443.
	call(user, peer, refused, servicecall.Refused)
	large := q
	large.Path = "/call-large"
	call(user, peer, large, servicecall.TooLarge)
	redirect := q
	redirect.Path = "/call-redirect"
	if result := call(user, peer, redirect, ""); result.Status != 302 {
		t.Fatal("redirect followed", result)
	}
	slow := q
	slow.Body = nil
	slow.Path = "/slow"
	slow.TimeoutMS = 1500
	call(user, peer, slow, servicecall.Timeout)
	absent := q
	absent.Service = "missing"
	call(user, peer, absent, servicecall.NoReadyTask)
	unixPeer := peer
	unixPeer.Endpoint = "unix://" + filepath.Join(root, "service-call.sock")
	if err := r.Mesh.ListenUnix(strings.TrimPrefix(unixPeer.Endpoint, "unix://")); err != nil {
		t.Fatal(err)
	}
	local := user
	var err error
	local.Mesh, err = sfcp.NewTransport(user.Self, user.Cluster, func(key sfcp.Identity) (sfcp.Peer, bool) { return unixPeer, key == unixPeer.Key })
	if err != nil {
		t.Fatal(err)
	}
	defer local.Mesh.Close()
	local.Peers = []sfcp.Peer{unixPeer}
	call(local, unixPeer, q, "")
	// Probe must not create/change an app CD source, candidate or active task.
	fingerprint := func() [32]byte {
		t.Helper()
		apps, err := p.ReadApps(read().State)
		if err != nil {
			t.Fatal(err)
		}
		delivery, ok := apps.Delivery("tenant", "app")
		if !ok {
			t.Fatal("missing ordinary CD registration")
		}
		candidate, found := delivery.CandidateSelection()
		selection, selected := delivery.Selection()
		execution, active := apps.Execution("tenant", "app")
		source, sourceFound := apps.DeliverySourceTarget("tenant", "app")
		if !sourceFound {
			t.Fatal("missing original source registration")
		}
		key := deployment.ResourceKey("task", "tenant", "app", "web")
		task, err := r.workload.View(key)
		if err != nil {
			t.Fatal(err)
		}
		native, err := r.workload.Status(ctx, key)
		if err != nil {
			t.Fatal(err)
		}
		var bindings [][32]byte
		for _, binding := range apps.Bindings().Live() {
			bindings = append(bindings, binding.Digest())
		}
		raw, err := json.Marshal(struct {
			Policy            deployment.DeliveryDeclaration
			Candidate         any
			Found             bool
			Selection         any
			Selected          bool
			Operation         string
			Active            bool
			Source            [32]byte
			Plan              [32]byte
			Task              any
			Bindings          [][32]byte
			Native, StartedAt string
		}{delivery.Policy(), candidate, found, selection, selected, execution.ActiveOperation(), active, source, execution.Blueprint().Digest(), task.State, bindings, native.NativeID, native.StartedAt})
		if err != nil {
			t.Fatal(err)
		}
		return sha256.Sum256(raw)
	}
	wait("ordinary registered Git source candidate", func() bool {
		apps, e := p.ReadApps(read().State)
		d, ok := apps.Delivery("tenant", "app")
		candidate, selected := d.CandidateSelection()
		return e == nil && ok && selected && candidate.Commit == commit
	})
	// Stop the ordinary registered poll through its original management API,
	// then join any already accepted read before comparing remote counters.
	// A probe is still permitted against this existing app while CD is paused.
	apps, err := p.ReadApps(read().State)
	if err != nil {
		t.Fatal(err)
	}
	delivery, _ := apps.Delivery("tenant", "app")
	change("rq8-probe-pause", "pause-app-cd", delivery.Revision(), control.AppCDChange{Tenant: "tenant", App: "app"})
	wait("original CD source paused and joined before diagnostic census", func() bool {
		apps, err := p.ReadApps(read().State)
		delivery, ok := apps.Delivery("tenant", "app")
		_, fetching := delivery.FetchTicket()
		return err == nil && ok && delivery.Paused() && !fetching && r.deliverySourceActive.Load() == 0
	})
	defer func() {
		apps, err := p.ReadApps(read().State)
		if err != nil {
			t.Error(err)
			return
		}
		delivery, ok := apps.Delivery("tenant", "app")
		if ok && delivery.Paused() {
			change("rq8-probe-resume", "resume-app-cd", delivery.Revision(), control.AppCDChange{Tenant: "tenant", App: "app"})
		}
	}()
	before := fingerprint()
	probe := deployment.GitProbeRequest{App: "app", Repository: source.Repository(), Branch: "main", Path: "app.yaml", Credential: "git-read"}
	result, err := user.ProbeCD(ctx, peer, session, "tenant", probe)
	if err != nil || result.Code != "" || result.Commit != commit || result.Size != int64(len(original)) || result.Node != cfg.Node.ID {
		t.Fatal("actual fixed Git probe", result, err)
	}
	if fingerprint() != before {
		t.Fatal("read-only probe changed CD policy/candidate/selection/app")
	}
	for _, bad := range []struct{ path, branch, credential, code string }{{"missing.yaml", "main", "git-read", "no-file"}, {"app.yaml", "missing", "git-read", "no-branch"}, {"app.yaml", "main", "missing", "no-credential"}} {
		attempt := probe
		attempt.Path, attempt.Branch, attempt.Credential = bad.path, bad.branch, bad.credential
		got, e := user.ProbeCD(ctx, peer, session, "tenant", attempt)
		if e != nil || got.Code != bad.code {
			t.Fatal("probe failure category", got, e)
		}
	}
	wrong := probe
	wrong.Credential = "git-bad"
	stats := source.Stats()
	denied, err := user.ProbeCD(ctx, peer, session, "tenant", wrong)
	if err != nil || denied.Code != "auth-failed" || denied.Commit != "" || denied.Size != 0 || source.Stats().Denied <= stats.Denied || source.Stats().Packs != stats.Packs {
		t.Fatal("actual trusted HTTPS source did not reject the distinct wrong token", denied.Code, err)
	}
	// Omitting credentials does not borrow another profile's CA or secret. The
	// owned self-signed source therefore fails TLS before its HTTP authenticator.
	anonymous := probe
	anonymous.Credential = ""
	stats = source.Stats()
	missingTrust, err := user.ProbeCD(ctx, peer, session, "tenant", anonymous)
	if err != nil || missingTrust.Code != "source-error" || missingTrust.Commit != "" || missingTrust.Size != 0 || !reflect.DeepEqual(stats, source.Stats()) {
		t.Fatal("anonymous request reused installed profile trust or reached source auth", missingTrust.Code, err)
	}
	if fingerprint() != before {
		t.Fatal("failed TLS/auth probes changed CD or app state")
	}
	cli := func(args ...string) []byte {
		t.Helper()
		body, diagnostic, e := runManagedCLICommand(ctx, os.Getenv("SFC_TEST_CLI"), filepath.Join(root, "cli-home"), filepath.Join(root, "cli.yaml"), append([]string{"--tenant", "tenant"}, args...), nil)
		if e != nil {
			t.Fatal("diagnostics actual CLI", e, string(body), string(diagnostic))
		}
		return body
	}
	var got servicecall.Result
	if err = json.Unmarshal(cli("service-call", "app", "web", "--port", "8443", "--path", "/call", "--scheme", "https"), &got); err != nil || got.Code != "" || got.Status != 200 {
		t.Fatal("CLI HTTPS actual Task", got, err)
	}
	var found deployment.GitProbeResult
	probeFile := filepath.Join(root, "probe-cd.yaml")
	rawProbe, err := yaml.Marshal(deployment.CDFile{Version: 1, Repository: source.Repository(), Branch: "main", Path: "app.yaml", Credential: "git-read"})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(probeFile, rawProbe, 0600); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(cli("cd", "probe", "app", "-f", probeFile), &found); err != nil || found.Commit != commit || found.Size != int64(len(original)) {
		t.Fatal("CLI read-only Git", found, err)
	}
	if !reflect.DeepEqual(before, fingerprint()) {
		t.Fatal("CLI probe changed app/CD state")
	}
	verifyManagedDiagnosticsAuthority(t, ctx, r, user, peer, p, read, wait, change, source, probe, q, want, commit, int64(len(original)), fingerprint)
	// The second installed voter is leader, while the native Task stays node-a.
	remote := prepareManagedHandoffControlAtReady(t, ctx, root, r, user, peer, session, p, read, change, func(c *config.Node) {
		c.GitCredentials = []config.GitCredential{source.Credential(root, "tenant", "rq8-provider-read")}
	}, func(provider *Runtime) {
		verifyManagedNonVoterCDProbe(t, ctx, r, provider, user, peer, p, read, change, source, probe, commit, int64(len(original)), fingerprint)
	})
	target, ok := r.Mesh.Peer(sfcp.Identity(remote.Identity.Public))
	if !ok {
		t.Fatal("remote installed voter")
	}
	if err = r.Engine().TransferLeadership(ctx, target.ID, target.Endpoint); err != nil {
		t.Fatal(err)
	}
	wait("remote diagnostics leader", remote.Engine().IsLeader)
	defer func() {
		if err := remote.Engine().TransferLeadership(ctx, peer.ID, peer.Endpoint); err != nil {
			t.Error(err)
			return
		}
		wait("restore diagnostics leader", r.Engine().IsLeader)
	}()
	call(user, peer, q, "") // Unix/QUIC user ingress -> leader -> exact native owner relay.
	call(local, unixPeer, secureHTTPS(q), "")
	return remote
}
func secureHTTPS(q servicecall.Request) servicecall.Request {
	q.Scheme = "https"
	q.Port = 8443
	return q
}

func verifyManagedServiceUnavailableAfterDown(t *testing.T, ctx context.Context, user userauth.Client, peer sfcp.Peer, session access.Session) {
	t.Helper()
	result, err := user.CallService(ctx, peer, session, "tenant", servicecall.Request{App: "app", Service: "web", Port: 8080, Path: "/call", Method: "POST"})
	if err != nil || !result.Valid() || result.Code != servicecall.NoReadyTask || result.Task != "" || len(result.Body) != 0 {
		t.Fatal("retired actual app still selected a ready native Task", result, err)
	}
}
