// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/moby/moby/client"
)

func TestRV5RealContainerSessionsAndOriginalExecRecovery(t *testing.T) {
	runManagedAppOwner(t, true, true, false, true, managedAppContainerSessions, true)
}

// Reuse the valid full-case assertions when only the post-Close election/
// original-ID recovery boundary changes. No marker claims the skipped cases.
func TestRV5RealOriginalExecRecoveryAndFinalClosure(t *testing.T) {
	runManagedAppOwner(t, true, true, false, true, managedAppExecRecovery, true)
}

type nativeSessionOutput struct {
	stdout, stderr bytes.Buffer
	receipt        containerops.ExecReceipt
	outputEOF      bool
	code           string
}

func (o *nativeSessionOutput) receive(t *testing.T, channel *userauth.ContainerChannel, until func(containerops.SessionRecord) bool) {
	t.Helper()
	for {
		r, err := channel.Receive()
		if err != nil {
			t.Fatal("native session record", err)
		}
		switch r.Kind {
		case "stdout":
			o.stdout.Write(r.Data)
		case "stderr":
			o.stderr.Write(r.Data)
		case "receipt":
			o.receipt = *r.Receipt
		case "output-eof":
			o.outputEOF = true
		case "error":
			o.code = r.Code
		}
		if until(r) {
			return
		}
		if r.Kind == "end" || r.Kind == "error" {
			t.Fatal("session ended before expected event", r.Kind, r.Code, o.stdout.String(), o.stderr.String())
		}
	}
}

func verifyManagedContainerSessions(t *testing.T, ctx context.Context, owner *Runtime, root string, user userauth.Client, peer sfcp.Peer, session access.Session, p control.Policy, read func() cluster.View, change func(string, string, uint64, any), fault *managedExecReplyFault, allCases bool) (func(*Runtime), func(), *Runtime) {
	t.Helper()
	selection := containerops.Selection{App: "app", Service: "web"}
	newIntent := func(c userauth.Client, targetPeer sfcp.Peer, grant access.Session, id string, spec containerops.SessionSpec) containerops.SessionIntent {
		t.Helper()
		target, err := c.ResolveContainerSession(ctx, targetPeer, grant, "tenant", selection, spec)
		if err != nil {
			t.Fatal("resolve actual native session", id, err)
		}
		i := containerops.SessionIntent{Schema: 1, Request: id, User: grant.User, Session: access.ExactSessionDigest(grant), At: time.Now().Unix(), Target: target, Spec: spec}
		i.Signature = ed25519.Sign(c.Self.Private, containerops.SessionIntentBytes(i))
		return i
	}
	open := func(c userauth.Client, targetPeer sfcp.Peer, grant access.Session, intent containerops.SessionIntent) *userauth.ContainerChannel {
		t.Helper()
		channel, err := c.OpenContainerSession(ctx, targetPeer, grant, intent, 10*time.Second)
		if err != nil {
			t.Fatal("open actual native session", intent.Request, err)
		}
		t.Cleanup(func() { _ = channel.Close() })
		return channel
	}
	send := func(channel *userauth.ContainerChannel, record containerops.SessionRecord) {
		t.Helper()
		if err := channel.Send(record); err != nil {
			t.Fatal("native session input", record.Kind, err)
		}
	}
	execSpec := func(mode string, input, tty bool) containerops.SessionSpec {
		q := &containerops.ExecSpec{Argv: []string{"/backend", mode}, Stdin: input, TTY: tty}
		if tty {
			q.Rows, q.Cols = 24, 80
		}
		return containerops.SessionSpec{Kind: "exec", Exec: q}
	}
	end := func(r containerops.SessionRecord) bool { return r.Kind == "end" || r.Kind == "error" }
	finished := func(o nativeSessionOutput, code int) {
		t.Helper()
		if o.code != "" || !o.outputEOF || o.receipt.Phase != containerops.ExecFinished || o.receipt.ExitCode == nil || *o.receipt.ExitCode != code {
			t.Fatal("actual exec exit", o.receipt, o.code, o.stdout.String(), o.stderr.String(), "want", code)
		}
	}
	var err error
	var ch *userauth.ContainerChannel
	var status containerops.ExecStatus
	if allCases {
		// Both transports use the real runtime, current quorum authorization and
		// Docker exec, rather than a test handler producing session records.
		unixPeer := peer
		unixPeer.Endpoint = "unix://" + filepath.Join(root, "session.sock")
		if err := owner.Mesh.ListenUnix(strings.TrimPrefix(unixPeer.Endpoint, "unix://")); err != nil {
			t.Fatal(err)
		}
		local := user
		local.Mesh, err = sfcp.NewTransport(user.Self, user.Cluster, func(key sfcp.Identity) (sfcp.Peer, bool) { return unixPeer, key == unixPeer.Key })
		if err != nil {
			t.Fatal(err)
		}
		defer local.Mesh.Close()
		local.Peers = []sfcp.Peer{unixPeer}
		for _, path := range []struct {
			name string
			c    userauth.Client
			peer sfcp.Peer
		}{{"quic", user, peer}, {"unix", local, unixPeer}} {
			spec := execSpec("--exec-args-fixture", false, false)
			spec.Exec.Argv = append(spec.Exec.Argv, "", "literal spaces", "-it")
			i := newIntent(path.c, path.peer, session, "args-"+path.name, spec)
			ch := open(path.c, path.peer, session, i)
			var out nativeSessionOutput
			out.receive(t, ch, end)
			finished(out, 0)
			var argv []string
			if json.Unmarshal(out.stdout.Bytes(), &argv) != nil || !reflect.DeepEqual(argv, spec.Exec.Argv[2:]) || out.stderr.Len() != 0 {
				t.Fatal("native argv changed", path.name, argv)
			}
			_ = ch.Close()
			t.Log("native argv/exit path", path.name, out.receipt.ExecID)
		}
		for _, tc := range []struct {
			id, input string
			code      int
		}{{"stdin-eof", "hello\n", 0}, {"exit-23", "exit 23\n", 23}} {
			i := newIntent(user, peer, session, tc.id, execSpec("--exec-io-fixture", true, false))
			ch := open(user, peer, session, i)
			send(ch, containerops.SessionRecord{Kind: "stdin", Data: []byte(tc.input)})
			send(ch, containerops.SessionRecord{Kind: "stdin-eof"})
			var out nativeSessionOutput
			out.receive(t, ch, end)
			finished(out, tc.code)
			if tc.code == 0 && (!strings.Contains(out.stdout.String(), "OUT hello\n") || !strings.Contains(out.stdout.String(), "exec-stdin-eof") || !strings.Contains(out.stderr.String(), "ERR hello\n") || !out.receipt.StdinClosed) {
				t.Fatal("half-close lost reverse output or stderr", out.stdout.String(), out.stderr.String(), out.receipt)
			}
			_ = ch.Close()
		}
		tty := newIntent(user, peer, session, "tty-resize-interrupt", execSpec("--exec-io-fixture", true, true))
		ch = open(user, peer, session, tty)
		var terminal nativeSessionOutput
		terminal.receive(t, ch, func(containerops.SessionRecord) bool {
			return strings.Contains(terminal.stdout.String(), "exec-io-ready")
		})
		send(ch, containerops.SessionRecord{Kind: "resize", Rows: 40, Cols: 100})
		send(ch, containerops.SessionRecord{Kind: "stdin", Data: []byte("size\n")})
		terminal.receive(t, ch, func(containerops.SessionRecord) bool {
			return strings.Contains(terminal.stdout.String(), "SIZE 40 100")
		})
		send(ch, containerops.SessionRecord{Kind: "stdin", Data: []byte{3}})
		terminal.receive(t, ch, end)
		finished(terminal, 130)
		if terminal.stderr.Len() != 0 {
			t.Fatal("TTY fabricated a separate stderr channel")
		}
		_ = ch.Close()
		t.Log("actual nonTTY stdin half-close/exit23 and TTY resize/interrupt/exit130 passed")
		// Missing shell is an explicit failed/uncertain start, never host fallback
		// or a fabricated successful zero exit after an uncertain Attach response.
		missing := newIntent(user, peer, session, "shell-absent", containerops.SessionSpec{Kind: "exec", Exec: &containerops.ExecSpec{Argv: []string{"/bin/sh"}}})
		ch = open(user, peer, session, missing)
		var shell nativeSessionOutput
		shell.receive(t, ch, end)
		if shell.code == "" && (shell.receipt.Phase != containerops.ExecFinished || shell.receipt.ExitCode == nil || *shell.receipt.ExitCode == 0) {
			t.Fatal("shell-free image did not report an explicit failure", shell.receipt)
		}
		_ = ch.Close()
		// This Engine retains Attach until process exit even after both process
		// output FDs close. Observe the live process before deliberately detaching;
		// do not assume closing an application FD produces a Docker stream EOF.
		// Independent output-EOF/receipt transitions are covered by the core test.
		eof := newIntent(user, peer, session, "output-eof-live", execSpec("--exec-closed-output-fixture", false, false))
		ch = open(user, peer, session, eof)
		var closed nativeSessionOutput
		closed.receive(t, ch, func(containerops.SessionRecord) bool {
			return strings.Contains(closed.stdout.String(), "exec-output-closing")
		})
		if closed.receipt.Phase != containerops.ExecStarted || closed.receipt.ExitCode != nil {
			t.Fatal("output FD close mistaken for process exit", closed.receipt)
		}
		status, err = user.ContainerExecStatus(ctx, peer, session, eof)
		if err != nil || status.Running == nil || !*status.Running || status.Receipt.ExecID != closed.receipt.ExecID {
			t.Fatal("live native after output FD close", err, status)
		}
		_ = ch.Close()
		t.Log("shell absence and actual live process after its output FD close passed")
		// Follow sees new output from the existing native. Read/write remain
		// concurrent so the HTTP writer cannot deadlock against log backpressure.
		q := containerops.Query{Schema: 1, Selection: selection, Kind: "logs", Tail: 1, Stdout: true, Stderr: true, MaxBytes: 16384}
		follow := newIntent(user, peer, session, "follow-original", containerops.SessionSpec{Kind: "logs", Query: &q})
		ch = open(user, peer, session, follow)
		var logs nativeSessionOutput
		logs.receive(t, ch, func(r containerops.SessionRecord) bool { return r.Kind == "sample" })
		native, err := owner.docker.API.ContainerInspect(ctx, follow.Target.NativeID, client.ContainerInspectOptions{})
		if err != nil || native.Container.NetworkSettings == nil {
			t.Fatal("follow original native address", err)
		}
		address := ""
		for _, n := range native.Container.NetworkSettings.Networks {
			if n.IPAddress.Is4() {
				address = n.IPAddress.String()
			}
		}
		if address == "" {
			t.Fatal("follow missing owned address")
		}
		httpDone := make(chan error, 1)
		go func() {
			request, e := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+address+":8080/logburst?marker=rv5-follow-new", nil)
			if e == nil {
				transport := &http.Transport{Proxy: nil}
				defer transport.CloseIdleConnections()
				var response *http.Response
				response, e = (&http.Client{Transport: transport, Timeout: 10 * time.Second}).Do(request)
				if e == nil {
					_, e = io.Copy(io.Discard, response.Body)
					_ = response.Body.Close()
					if response.StatusCode != http.StatusNoContent {
						e = fmt.Errorf("owned log endpoint status %d", response.StatusCode)
					}
				}
			}
			httpDone <- e
		}()
		logs.receive(t, ch, func(containerops.SessionRecord) bool {
			return strings.Contains(logs.stdout.String(), "rv5-follow-new-031:")
		})
		_ = ch.Close()
		if err = <-httpDone; err != nil {
			t.Fatal("follow actual new log write", err)
		}
		for _, kind := range []string{"top", "stats"} {
			query := containerops.Query{Schema: 1, Selection: selection, Kind: kind, MaxBytes: 16384}
			i := newIntent(user, peer, session, "watch-"+kind, containerops.SessionSpec{Kind: kind, Query: &query, Interval: time.Second})
			watch := open(user, peer, session, i)
			var previous time.Time
			for count := 0; count < 2; {
				record, e := watch.Receive()
				if e != nil || record.Kind == "error" || record.Kind == "end" {
					t.Fatal("actual watch sample", kind, e, record.Code)
				}
				if record.Kind == "sample" {
					if !record.Sample.ObservedAt.After(previous) || record.Sample.Target.NativeID != i.Target.NativeID {
						t.Fatal("watch repeated sample or rebound native", kind)
					}
					previous = record.Sample.ObservedAt
					count++
				}
			}
			_ = watch.Close()
		}
		// Exercise CLI follow before explicit log retirement removes its marker.
		verifyManagedSessionCLI(t, ctx, root)
		// Replace the owned native through the already supported explicit app
		// recreation path. Bypassing app lifecycle with a direct SDK restart has
		// no accepted restart proof and must not become a new app instance.
		restartQuery := containerops.Query{Schema: 1, Selection: selection, Kind: "stats", MaxBytes: 16384}
		restartSpec := containerops.SessionSpec{Kind: "stats", Query: &restartQuery, Interval: time.Second}
		beforeRestart := newIntent(user, peer, session, "watch-native-restart", restartSpec)
		restartWatch := open(user, peer, session, beforeRestart)
		var firstRestartSample nativeSessionOutput
		firstRestartSample.receive(t, restartWatch, func(r containerops.SessionRecord) bool { return r.Kind == "sample" })
		_, diagnostic, err := runManagedCLICommand(ctx, os.Getenv("SFC_TEST_CLI"), filepath.Join(root, "cli-home"), filepath.Join(root, "cli.yaml"), []string{"--tenant", "tenant", "compose", "logs-clear", "-p", "app", "web", "--recreate", "--operation", "stream-replacement"}, nil)
		if err != nil {
			t.Fatal("explicit owned app replacement", err, string(diagnostic))
		}
		stopRestartWatch := time.AfterFunc(9*time.Second, func() { _ = restartWatch.Close() })
		for {
			record, e := restartWatch.Receive()
			if e != nil || record.Kind == "error" || record.Kind == "end" {
				break
			}
			if record.Sample != nil && record.Sample.Target != beforeRestart.Target {
				t.Fatal("watch rebound to restarted native lifetime")
			}
		}
		if !stopRestartWatch.Stop() {
			t.Fatal("native restart did not stop original watch")
		}
		_ = restartWatch.Close()
		for {
			target, e := user.ResolveContainerSession(ctx, peer, session, "tenant", selection, restartSpec)
			apps, decodeErr := p.ReadApps(read().State)
			current, exists := apps.Execution("tenant", "app")
			if e == nil && decodeErr == nil && exists && current.Status() == "Succeeded" && current.ActiveOperation() == "stream-replacement" && target.NativeID != beforeRestart.Target.NativeID && target.StartedAt != beforeRestart.Target.StartedAt {
				break
			}
			select {
			case <-ctx.Done():
				t.Fatal("fresh owner report after explicit app replacement", ctx.Err(), e)
			case <-time.After(50 * time.Millisecond):
			}
		}
		if stale, e := user.OpenContainerSession(ctx, peer, session, beforeRestart, 10*time.Second); e == nil {
			_ = stale.Close()
			t.Fatal("old signed intent accepted after native lifetime replacement")
		}
		t.Log("actual follow/watch new samples and explicitly accepted native lifetime replacement passed")
		verifyManagedSessionDenials(t, ctx, owner, user, peer, session, p, read, change, newIntent, open, execSpec)
		lost := newIntent(user, peer, session, "attach-response-lost", execSpec("--exec-detach-fixture", false, false))
		fault.arm(lost.Target.NativeID)
		lostChannel := open(user, peer, session, lost)
		var lostOutput nativeSessionOutput
		lostOutput.receive(t, lostChannel, end)
		_ = lostChannel.Close()
		if lostOutput.code == "" || lostOutput.receipt.Phase != containerops.ExecStartSent || lostOutput.receipt.ExitCode != nil {
			t.Fatal("lost Attach response became a successful/terminal start", lostOutput.receipt, lostOutput.code)
		}
		lostStatus, err := user.ContainerExecStatus(ctx, peer, session, lost)
		if err != nil || lostStatus.Running == nil || !*lostStatus.Running || lostStatus.Receipt.ExecID != lostOutput.receipt.ExecID {
			t.Fatal("actual effect after lost Attach response", err, lostStatus)
		}
		retry := open(user, peer, session, lost)
		var recoveredLost nativeSessionOutput
		recoveredLost.receive(t, retry, end)
		_ = retry.Close()
		creates, starts, dropped := fault.snapshot()
		if creates != 1 || starts != 1 || !dropped || recoveredLost.receipt.ExecID != lostOutput.receipt.ExecID || recoveredLost.stdout.Len() != 0 {
			t.Fatal("lost response replayed native Create/Attach", creates, starts, dropped, recoveredLost.receipt)
		}
		fault.disarm()
	}
	// A second installed control receives the user stream and forwards it to
	// the original Docker owner. Its read/permit path uses the real new leader.
	remote := prepareManagedHandoffControl(t, ctx, root, owner, user, peer, session, p, read, change)
	remotePeer, ok := owner.Mesh.Peer(sfcp.Identity(remote.Identity.Public))
	if !ok {
		t.Fatal("session remote installed peer")
	}
	if err = owner.Engine().TransferLeadership(ctx, remotePeer.ID, remotePeer.Endpoint); err != nil {
		t.Fatal(err)
	}
	for !remote.Engine().IsLeader() {
		select {
		case <-ctx.Done():
			t.Fatal("session remote election", ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	if _, err = remote.Engine().Read(ctx, true); err != nil {
		t.Fatal("session remote barrier", err)
	}
	routed := user
	routed.Mesh, err = sfcp.NewTransport(user.Self, user.Cluster, func(key sfcp.Identity) (sfcp.Peer, bool) { return remotePeer, key == remotePeer.Key })
	if err != nil {
		t.Fatal(err)
	}
	defer routed.Mesh.Close()
	// The endpoint changes, while the original installed issuer pin remains.
	routed.Peers = []sfcp.Peer{peer, remotePeer}
	routeIntent := newIntent(routed, remotePeer, session, "remote-owner-exec", execSpec("--exec-args-fixture", false, false))
	remoteChannel := open(routed, remotePeer, session, routeIntent)
	var remoteOutput nativeSessionOutput
	remoteOutput.receive(t, remoteChannel, end)
	finished(remoteOutput, 0)
	_ = remoteChannel.Close()
	if routeIntent.Target.Owner != owner.Identity.Public {
		t.Fatal("remote ingress changed native owner")
	}
	if err = remote.Engine().TransferLeadership(ctx, peer.ID, peer.Endpoint); err != nil {
		t.Fatal("restore session fixture leader", err)
	}
	for !owner.Engine().IsLeader() {
		select {
		case <-ctx.Done():
			t.Fatal("restore session election", ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	if _, err = owner.Engine().Read(ctx, true); err != nil {
		t.Fatal(err)
	}
	// Keep one real sleeping exec at daemon Close. Closing its attached stream
	// is not a process kill; reopening the same owner DB only inspects its ID.
	original := newIntent(user, peer, session, "detach-original", execSpec("--exec-detach-fixture", false, false))
	ch = open(user, peer, session, original)
	var detached nativeSessionOutput
	detached.receive(t, ch, func(containerops.SessionRecord) bool {
		return strings.Contains(detached.stdout.String(), "exec-detach-ready")
	})
	_ = ch.Close()
	status, err = user.ContainerExecStatus(ctx, peer, session, original)
	if err != nil || status.Running == nil || !*status.Running || status.Receipt.ExecID != detached.receipt.ExecID || status.Receipt.ExitCode != nil {
		t.Fatal("disconnected process not actually alive", err, status)
	}
	// Explicit duplicate original open is metadata only; it cannot reAttach.
	duplicate := open(user, peer, session, original)
	var repeated nativeSessionOutput
	repeated.receive(t, duplicate, end)
	_ = duplicate.Close()
	if repeated.stdout.Len()+repeated.stderr.Len() != 0 || repeated.receipt.ExecID != detached.receipt.ExecID {
		t.Fatal("original exec replayed or reattached", repeated.receipt)
	}
	shutdownIntent := newIntent(user, peer, session, "daemon-close-live", execSpec("--exec-detach-fixture", false, false))
	shutdownChannel := open(user, peer, session, shutdownIntent)
	var shutdownOutput nativeSessionOutput
	shutdownOutput.receive(t, shutdownChannel, func(containerops.SessionRecord) bool {
		return strings.Contains(shutdownOutput.stdout.String(), "exec-detach-ready")
	})
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		for {
			r, err := shutdownChannel.Receive()
			if err != nil || r.Kind == "end" || r.Kind == "error" {
				return
			}
		}
	}()
	t.Cleanup(func() { _ = shutdownChannel.Close(); <-shutdownDone })
	var stopWatch *userauth.ContainerChannel
	stoppedWatch := make(chan struct{})
	recovered := func(reopened *Runtime) {
		if reopened == owner {
			t.Fatal("expected real daemon/DB reopen")
		}
		// Open/InstallConfiguration restores local DB/config, not an elected
		// quorum. Preserve the original IDs and establish the same actual
		// control barrier used by the existing recovered-observation fixture.
		for {
			if reopened.Engine().IsLeader() {
				v, e := reopened.Engine().Read(ctx, true)
				if e == nil && !v.Local && v.RaftIndex != 0 {
					break
				}
				if e != nil && !errors.Is(e, raft.ErrNotLeader) && !errors.Is(e, raft.ErrLeadershipLost) {
					t.Fatal("reopened quorum barrier", e)
				}
			} else if remote.Engine().IsLeader() {
				if e := remote.Engine().TransferLeadership(ctx, peer.ID, peer.Endpoint); e != nil && !errors.Is(e, raft.ErrNotLeader) && !errors.Is(e, raft.ErrLeadershipLost) {
					t.Fatal("restore reopened owner leadership", e)
				}
			}
			select {
			case <-ctx.Done():
				t.Fatal("reopened control election", ctx.Err())
			case <-time.After(20 * time.Millisecond):
			}
		}
		got, e := user.ContainerExecStatus(ctx, peer, session, original)
		if e != nil || got.Receipt.ExecID != detached.receipt.ExecID || got.Target != original.Target || got.Running == nil {
			row, storeErr := reopened.userExecRecord(original)
			_, directErr := reopened.containerExecStatus(ctx, session, original)
			t.Log("retained original diagnostic", "store", storeErr, "phase", row.Receipt.Phase, "direct status", directErr, "leader", reopened.Engine().IsLeader())
			t.Fatal("same DB original exec status", e, got)
		}
		if got.Running != nil && *got.Running && got.Receipt.ExitCode != nil {
			t.Fatal("live original got fictitious exit")
		}
		t.Log("retained original ExecID after actual DB reopen", got.Receipt.ExecID, "phase", got.Receipt.Phase)
		select {
		case <-shutdownDone:
		case <-time.After(5 * time.Second):
			t.Fatal("daemon close retained live session I/O")
		}
		query := containerops.Query{Schema: 1, Selection: selection, Kind: "top", MaxBytes: 16384}
		i := newIntent(user, peer, session, "watch-until-original-stop", containerops.SessionSpec{Kind: "top", Query: &query, Interval: time.Second})
		stopWatch = open(user, peer, session, i)
		var first nativeSessionOutput
		first.receive(t, stopWatch, func(r containerops.SessionRecord) bool { return r.Kind == "sample" })
		go func() {
			defer close(stoppedWatch)
			for {
				r, err := stopWatch.Receive()
				if err != nil || r.Kind == "end" || r.Kind == "error" {
					return
				}
			}
		}()
		t.Cleanup(func() { _ = stopWatch.Close(); <-stoppedWatch })
	}
	return recovered, func() {
		select {
		case <-stoppedWatch:
		case <-time.After(5 * time.Second):
			_ = stopWatch.Close()
			<-stoppedWatch
			t.Fatal("original container termination retained watch")
		}
		t.Log("actual daemon loss and original Task termination close I/O without generation rebind")
	}, remote
}

func verifyManagedSessionDenials(t *testing.T, ctx context.Context, owner *Runtime, user userauth.Client, peer sfcp.Peer, session access.Session, p control.Policy, read func() cluster.View, change func(string, string, uint64, any), makeIntent func(userauth.Client, sfcp.Peer, access.Session, string, containerops.SessionSpec) containerops.SessionIntent, start func(userauth.Client, sfcp.Peer, access.Session, containerops.SessionIntent) *userauth.ContainerChannel, spec func(string, bool, bool) containerops.SessionSpec) {
	t.Helper()
	selection := containerops.Selection{App: "app", Service: "web"}
	// Test-issued grants are signed by the actual installed active issuer.
	// They keep the real registered account/credential/proof key, and alter
	// only the claimed ceiling/lifetime to exercise current enforcement.
	grant := func(id string) access.Session {
		s := session
		s.ID, s.Approval = id, nil
		s.Signature = ed25519.Sign(owner.Identity.Private, access.SessionBytes(s))
		return s
	}
	for _, action := range []access.Action{access.Read, access.Deploy} {
		s := grant("rv5-limited-" + string(action))
		s.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{action}}}
		s.Signature = ed25519.Sign(owner.Identity.Private, access.SessionBytes(s))
		if _, err := user.ResolveContainerSession(ctx, peer, s, "tenant", selection, spec("--exec-args-fixture", false, false)); err == nil {
			t.Fatal("exec omitted Read or Deploy scope", action)
		}
	}
	valid := makeIntent(user, peer, session, "forged-node-intent", spec("--exec-args-fixture", false, false))
	valid.Signature = ed25519.Sign(owner.Identity.Private, containerops.SessionIntentBytes(valid))
	if ch, err := user.OpenContainerSession(ctx, peer, session, valid, 10*time.Second); err == nil {
		_ = ch.Close()
		t.Fatal("installed node signed new user exec intent")
	}
	if _, err := owner.userExecRecord(valid); err == nil {
		t.Fatal("forged user intent reached owner effect journal")
	}
	for _, mode := range []string{"expiry", "revoke"} {
		s := grant("rv5-" + mode)
		if mode == "expiry" {
			s.ExpiresAt = time.Now().Add(5 * time.Second).Unix()
			s.Signature = ed25519.Sign(owner.Identity.Private, access.SessionBytes(s))
		}
		i := makeIntent(user, peer, s, "auth-"+mode, spec("--exec-detach-fixture", false, false))
		ch := start(user, peer, s, i)
		var out nativeSessionOutput
		out.receive(t, ch, func(containerops.SessionRecord) bool {
			return strings.Contains(out.stdout.String(), "exec-detach-ready")
		})
		if mode == "revoke" {
			catalog, err := p.Catalog(read().State)
			account, ok := catalog.User(session.User)
			if err != nil || !ok {
				t.Fatal("revoke test grant account", err)
			}
			change("rv5-revoke-live-session", "revoke-session", account.Revision, control.SessionRevocation{User: session.User, Session: s.ID})
		}
		// A root-bound deadline prevents a broken revocation guard from making
		// this fixture wait for the 30-second native process to exit naturally.
		stop := time.AfterFunc(9*time.Second, func() { _ = ch.Close() })
		terminated := false
		for !terminated {
			record, err := ch.Receive()
			terminated = err != nil || record.Kind == "error" || record.Kind == "end"
		}
		inTime := stop.Stop()
		_ = ch.Close()
		if !inTime {
			t.Fatal("auth loss did not stop live I/O", mode)
		}
		current, err := user.ContainerExecStatus(ctx, peer, session, i)
		if err != nil || current.Running == nil || !*current.Running || current.Receipt.ExecID != out.receipt.ExecID || current.Receipt.ExitCode != nil {
			t.Fatal("auth loss was mistaken for process kill", mode, err, current)
		}
	}
	// Deliberately do not read this finite 1MiB stream. The receiver's fixed
	// initial QUIC window fills and the owner's write deadline detaches I/O.
	i := makeIntent(user, peer, session, "slow-reader", spec("--exec-burst-fixture", false, false))
	ch := start(user, peer, session, i)
	defer ch.Close()
	until := time.NewTimer(12 * time.Second)
	defer until.Stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		row, err := owner.userExecRecord(i)
		if err == nil && row.Receipt.Detached {
			t.Log("slow reader detached original I/O", row.Receipt.ExecID)
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-until.C:
			t.Fatal("slow reader retained owner I/O beyond write budget", err)
		case <-tick.C:
		}
	}
}

func verifyManagedSessionCLI(t *testing.T, ctx context.Context, root string) {
	t.Helper()
	call := func(want int, args ...string) []byte {
		t.Helper()
		body, diagnostic, err := runManagedCLICommand(ctx, os.Getenv("SFC_TEST_CLI"), filepath.Join(root, "cli-home"), filepath.Join(root, "cli.yaml"), append([]string{"--tenant", "tenant"}, args...), nil)
		code := 0
		if err != nil {
			if exited, ok := err.(interface{ ExitCode() int }); ok {
				code = exited.ExitCode()
			} else {
				t.Fatal("session CLI child", err)
			}
		}
		if code != want {
			t.Fatal("session CLI exit", code, "want", want, string(diagnostic), string(body))
		}
		return body
	}
	args := []string{"compose", "exec", "-p", "app", "--operation", "cli-original", "web", "--", "/backend", "--exec-args-fixture", "", "literal spaces", "-it"}
	first := call(0, args...)
	var argv []string
	if json.Unmarshal(first, &argv) != nil || !reflect.DeepEqual(argv, []string{"", "literal spaces", "-it"}) {
		t.Fatal("CLI changed literal argv", string(first))
	}
	// A second invocation finds its local original journal first and only
	// queries status; stdout contains metadata, never repeated process output.
	repeated := call(0, args...)
	statusBody := call(0, "compose", "exec-status", "-p", "app", "--operation", "cli-original")
	var before, after containerops.ExecStatus
	if json.Unmarshal(repeated, &before) != nil || json.Unmarshal(statusBody, &after) != nil || before.Receipt.ExecID == "" || before.Receipt.ExecID != after.Receipt.ExecID || after.Receipt.Phase != containerops.ExecFinished {
		t.Fatal("CLI original status did not retain native", string(repeated), string(statusBody))
	}
	body, diagnostic, err := runManagedCLICommandInput(ctx, os.Getenv("SFC_TEST_CLI"), filepath.Join(root, "cli-home"), filepath.Join(root, "cli.yaml"), []string{"--tenant", "tenant", "compose", "exec", "-p", "app", "--operation", "cli-input-original", "-i", "web", "--", "/backend", "--exec-io-fixture"}, nil, strings.NewReader("cli-input\nexit 23\n"))
	exited, ok := err.(interface{ ExitCode() int })
	if !ok || exited.ExitCode() != 23 || !bytes.Contains(body, []byte("OUT cli-input")) || !bytes.Contains(diagnostic, []byte("ERR cli-input")) {
		t.Fatal("CLI actual bidirectional input/exit", err, string(body), string(diagnostic))
	}
	verifyManagedSessionCLITerminal(t, ctx, root)
	verifyManagedSessionCLIWatch(t, ctx, root)
}
