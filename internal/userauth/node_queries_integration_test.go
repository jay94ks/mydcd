// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/membership"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/wallet"
)

// Reuses the actual SDK Raft/bbolt and authenticated transport fixture. Member
// installation acknowledgements and signed shell owner reports are explicit
// modeled inputs: this root does not claim Docker evacuation or SSH execution.
// The new drain is genuinely accepted through the ordinary User management
// API, with an empty Task plan; no original ID is supplied to its discoverer.
func TestRQ15NodeQueriesActualRaftUnixQUICAndCLI(t *testing.T) {
	binary := os.Getenv("MYDC_TEST_CLI")
	if !filepath.IsAbs(binary) {
		t.Skip("requires explicitly prebuilt final mydc")
	}
	f := newVolumeFileWireFixture(t)
	f.session.Scopes = fullUserScopes()
	f.session.Signature = ed25519.Sign(f.nodes[0].Private, access.SessionBytes(f.session))
	root := t.TempDir()

	// The shared fixture deliberately leads on node-b. As in the existing
	// shell relay root, install that member through signed original inputs
	// before asking its real User Service to consume forwarded requests.
	member := config.Peer{ID: f.peers[1].ID, Key: hex.EncodeToString(f.nodes[1].Public[:]), Endpoint: f.peers[1].Endpoint}
	f.change("invite-node", 0, control.NodeInvitation{Peer: member, JoinID: "query-member-b"})
	memberReport := func(action string, edit func(*control.MemberReport)) {
		t.Helper()
		v := f.read()
		directory, err := f.policy.Members(v.State)
		if err != nil {
			t.Fatal(err)
		}
		entry, _ := directory.Entry(member.ID)
		r := control.MemberReport{Schema: 1, Cluster: f.policy.Cluster, Reporter: f.nodes[0].Public, Action: action, Node: member.ID, Expected: entry.Revision, Epoch: v.State.ModuleEpoch(), RootRevision: v.State.Object(control.MembersKey).Revision, RequestID: "query-member-" + action}
		edit(&r)
		r.Signature = ed25519.Sign(f.nodes[0].Private, control.MemberReportBytes(r))
		cmd, err := r.Command()
		if err != nil {
			t.Fatal(err)
		}
		f.submit(cmd)
	}
	memberReport("dispatch", func(r *control.MemberReport) {
		directory, _ := f.policy.Members(f.read().State)
		entry, _ := directory.Entry(member.ID)
		r.JobID, r.ConfigurationIndex = entry.Job.Pending.ID, f.read().RaftIndex
	})
	memberReport("observe", func(r *control.MemberReport) {
		directory, _ := f.policy.Members(f.read().State)
		entry, _ := directory.Entry(member.ID)
		r.JobID, r.ConfigurationIndex, r.Peer = entry.Job.Pending.ID, f.read().RaftIndex, member
	})
	memberReport("installed", func(r *control.MemberReport) {
		directory, _ := f.policy.Members(f.read().State)
		entry, _ := directory.Entry(member.ID)
		ack := membership.Ack{Schema: 1, Cluster: f.policy.Cluster, Node: member.ID, JoinID: entry.JoinID, Key: f.nodes[1].Public, ConfigurationIndex: entry.NativeIndex, AppliedIndex: f.read().RaftIndex}
		ack.Signature = ed25519.Sign(f.nodes[1].Private, membership.AckBytes(ack))
		r.Ack = &ack
	})
	for i := 0; i < 2; i++ {
		service := Service{Engine: f.engines[i], Mesh: f.meshes[i], Self: f.nodes[i], Policy: f.policy}
		if err := service.Serve(); err != nil {
			t.Fatal(err)
		}
	}
	socket := filepath.Join(root, "queries.sock")
	if err := f.meshes[0].ListenUnix(socket); err != nil {
		t.Fatal(err)
	}
	observerKey, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(observerKey.Private)
	f.change("put-user", 0, access.User{ID: "query-observer", Username: "query.observer", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: observerKey.Public, Enabled: true}}})
	book, err := f.policy.NodeShells(f.read().State)
	if err != nil {
		t.Fatal(err)
	}
	f.change("set-node-shell-node", book.Policy.Revision, control.NodeShellNodeChange{Node: f.peers[0].ID, Shell: "on"})
	report := func(kind, id string) {
		t.Helper()
		v := f.read()
		book, err := f.policy.NodeShells(v.State)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().Unix()
		r := control.NodeShellReport{Schema: 1, Cluster: f.policy.Cluster, Reporter: f.nodes[0].Public, Node: f.peers[0].ID, Kind: kind, SessionID: id, Epoch: v.State.ModuleEpoch(), RootRevision: v.State.Object(control.NodeShellKey).Revision, PolicyRevision: book.Policy.Revision, RequestID: fmt.Sprintf("query-report-%d", v.State.Index()), At: now, Sequence: 1}
		if kind == "ready" {
			r.Ready = true
		} else {
			original, found := book.Record(id)
			if !found {
				t.Fatal("missing original owner report target")
			}
			r.LastActivity = original.Session.LastActivity
			if original.Report != nil {
				r.Sequence = original.Report.Sequence + 1
			}
			if kind == "opened" {
				r.LastActivity = now
			} else if kind == "closed" {
				// Model a positively observed failed SSH attempt, not success
				// inferred from a missing native observation.
				r.Code, r.Reason = 255, "exit"
			}
		}
		r.Signature = ed25519.Sign(f.nodes[0].Private, control.NodeShellReportBytes(r))
		cmd, err := r.Command()
		if err != nil {
			t.Fatal(err)
		}
		f.submit(cmd)
	}
	report("ready", "")
	var originals []state.Command
	var originalResults []state.Result
	open := func(id string) {
		t.Helper()
		raw, err := control.ChangeBytes("open-node-shell", f.session.User, 0, control.NodeShellOpen{Node: f.peers[0].ID, Cols: 80, Rows: 24})
		if err != nil {
			t.Fatal(err)
		}
		var change control.Change
		if json.Unmarshal(raw, &change) != nil {
			t.Fatal("original shell change")
		}
		v := f.read()
		op := control.UserOperation{Schema: 1, Session: f.session, At: time.Now().Unix(), Epoch: v.State.ModuleEpoch(), RootRevision: v.State.Object(control.NodeShellKey).Revision, RequestID: id, Change: change}
		op.Signature = ed25519.Sign(f.user.Private, control.OperationBytes(op))
		cmd, err := op.Command()
		if err != nil {
			t.Fatal(err)
		}
		f.submit(cmd)
		result, found := f.read().State.LookupResult(cmd)
		if !found || result.Code != state.Applied {
			t.Fatal("missing exact committed shell receipt")
		}
		originals, originalResults = append(originals, cmd), append(originalResults, result)
	}
	for i := 0; i < 10; i++ {
		id := fmt.Sprintf("closed-%02d", i)
		open(id)
		report("closed", id)
	}
	open("live-queued")
	open("live-opened")
	report("opened", "live-opened")
	open("live-closing")
	f.change("close-node-shell", 0, control.NodeShellClose{SessionID: "live-closing"})

	// The actual management API plans and accepts the original drain. This
	// fixture has no deployed Tasks, so its Succeeded result makes no claim
	// about moving containers, Volume contents or closing native resources.
	plan, err := f.client.NodeDrainPlan(f.ctx, f.peers[0], f.session, control.NodeDrainQuery{Node: f.peers[0].ID, Operation: "query-original-drain"})
	if err != nil || len(plan.Tasks) != 0 || len(plan.Jobs) != 0 || len(plan.Blockers) != 0 {
		t.Fatal("actual empty-task drain plan", err)
	}
	raw, err := control.ChangeBytes("drain-node", f.session.User, plan.Expected, control.NodeDrainChange{At: plan.At, ID: plan.Node, Operation: plan.Operation, AppsRoot: plan.AppsRoot, Plan: plan.Digest, Jobs: plan.Jobs})
	if err != nil {
		t.Fatal(err)
	}
	var change control.Change
	if json.Unmarshal(raw, &change) != nil {
		t.Fatal("original drain change")
	}
	drain, err := f.client.Prepare(f.ctx, f.peers[0], f.session, "query-drain-command", change)
	if err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(root, "original-journal")
	if err := os.MkdirAll(journal, 0700); err != nil {
		t.Fatal("owned original journal home", err)
	}
	if _, err = StageOperation(journal, f.client, drain); err != nil {
		t.Fatal(err)
	}
	accepted, err := f.client.Operation(f.ctx, f.peers[0], drain, false)
	if err != nil || accepted.Result == nil || accepted.Result.Code != state.Applied {
		t.Fatal("actual original drain acceptance", err)
	}
	if err := RecordOperationResult(journal, f.client, f.session, drain, *accepted.Result); err != nil {
		t.Fatal(err)
	}
	drainCommand, err := drain.Command()
	if err != nil {
		t.Fatal(err)
	}
	originals, originalResults = append(originals, drainCommand), append(originalResults, *accepted.Result)
	before := f.read().State.Object(control.NodeShellKey)
	membersBefore := f.read().State.Object(control.MembersKey)

	type target struct {
		client  Client
		peer    mydcp.Peer
		session access.Session
		call    func(...string) ([]byte, int)
	}
	var targets []target
	for _, network := range []string{"unix", "quic"} {
		t.Log("actual query transport:", network)
		{
			peer := f.peers[0]
			if network == "unix" {
				peer.Endpoint = "unix://" + socket
			}
			client := f.client
			client.Peers = []mydcp.Peer{peer}
			// A profile's transport pins the selected endpoint too. Replacing
			// Client.Peers cannot turn the fixture's QUIC pin into a Unix pin.
			mesh, err := mydcp.NewTransport(f.user, f.policy.Cluster, func(key mydcp.Identity) (mydcp.Peer, bool) {
				return peer, key == peer.Key
			})
			if err != nil {
				t.Fatal("selected endpoint transport", err)
			}
			t.Cleanup(func() { _ = mesh.Close() })
			client.Mesh = mesh
			observer, err := client.Login(f.ctx, peer, "query.observer", observerKey.Private)
			if err != nil || observer.User == f.session.User {
				t.Fatal("actual different administrator login", err)
			}
			call := rq15NodeQueryCLI(t, f.ctx, binary, filepath.Join(root, network), client, peer, observerKey)
			verifyRQ15NodeQueries(t, f.ctx, client, peer, observer, call, plan.Operation)
			// The new administrator has no local original drain record, even
			// though both actual SDK and CLI discovered its committed identity.
			if _, err := LoadOperation(filepath.Join(root, network, "home"), client, observer, drain.RequestID); !errors.Is(err, ErrOperationMissing) {
				t.Fatal("discovery depended on or copied another user's journal", err)
			}
			targets = append(targets, target{client, peer, observer, call})
		}
	}
	if len(targets) != 2 {
		t.Fatal("both real transport consumers must complete")
	}
	if after := f.read().State.Object(control.NodeShellKey); after != before {
		t.Fatal("query changed the original signed book or owner receipts")
	}
	if after := f.read().State.Object(control.MembersKey); after != membersBefore {
		t.Fatal("discovery changed the original drain, signed origin or cordon")
	}
	for i, cmd := range originals {
		result, found := f.read().State.LookupResult(cmd)
		if !found || result != originalResults[i] {
			t.Fatal("query changed an original accepted operation result")
		}
	}

	// Demote only the additional observer. Preserve the original administrator
	// and all original shell/drain rows; stale sessions cannot retain old roles.
	catalog, err := f.policy.Catalog(f.read().State)
	if err != nil {
		t.Fatal(err)
	}
	observer, found := catalog.User("query-observer")
	if !found {
		t.Fatal("separate observer missing")
	}
	expected := observer.Revision
	observer.Revision, observer.SystemAdmin = 0, false
	f.change("put-user", expected, observer)
	for _, target := range targets {
		if _, err := target.client.NodeShellSessions(f.ctx, target.peer, target.session, "", control.NodeShellSessionsQuery{State: "open"}); err == nil {
			t.Fatal("cached revoked account revision still queried shell rows")
		}
		if _, err := target.client.NodeDrainStatus(f.ctx, target.peer, target.session, control.NodeDrainQuery{Node: f.peers[0].ID}); err == nil {
			t.Fatal("cached administrator still discovered another user's drain")
		}
		for _, args := range [][]string{{"node", "shell-sessions", "--state", "open"}, {"node", "drain-status", f.peers[0].ID}} {
			if _, code := target.call(args...); code != 3 {
				t.Fatal("actual CLI did not refuse the revoked current role", code)
			}
		}
		ordinary, err := target.client.Login(f.ctx, target.peer, "query.observer", observerKey.Private)
		if err != nil {
			t.Fatal("current ordinary-user login", err)
		}
		page, err := target.client.NodeShellSessions(f.ctx, target.peer, ordinary, "", control.NodeShellSessionsQuery{State: "open", Node: f.peers[0].ID})
		if err != nil || page.NodeShellSessions == nil || page.NodeShellSessions.Total != 0 || len(page.NodeShellSessions.Sessions) != 0 || page.NodeShellSessions.Next != "" {
			t.Fatal("ordinary user saw another user's rows/count/cursor", err)
		}
		if _, err := target.client.NodeDrainStatus(f.ctx, target.peer, ordinary, control.NodeDrainQuery{Node: f.peers[0].ID}); err == nil {
			t.Fatal("fresh non-administrator discovered a system drain")
		}
	}
	if _, err := f.client.NodeDrainStatus(f.ctx, f.peers[0], f.session, control.NodeDrainQuery{Node: f.peers[0].ID, Operation: plan.Operation}); err != nil {
		t.Fatal("observer revocation damaged original administrator access", err)
	}
}

func verifyRQ15NodeQueries(t *testing.T, ctx context.Context, client Client, peer mydcp.Peer, session access.Session, call func(...string) ([]byte, int), operation string) {
	t.Helper()
	for _, test := range []struct {
		filter control.NodeShellSessionsQuery
		after  string
		total  int
		count  int
		next   string
	}{
		{control.NodeShellSessionsQuery{}, "", 13, 8, "closed-07"},
		{control.NodeShellSessionsQuery{State: "open", Node: peer.ID}, "", 3, 3, ""},
		{control.NodeShellSessionsQuery{State: "closed", Node: peer.ID}, "", 10, 8, "closed-07"},
		{control.NodeShellSessionsQuery{State: "closed", Node: peer.ID}, "closed-07", 10, 2, ""},
		{control.NodeShellSessionsQuery{State: "closed", Node: peer.ID}, "closed-99", 10, 0, ""},
		{control.NodeShellSessionsQuery{State: "open", Node: "node-b"}, "", 0, 0, ""},
	} {
		var reply Reply
		var err error
		if test.filter == (control.NodeShellSessionsQuery{}) {
			reply, err = client.NodeShellSessions(ctx, peer, session, test.after)
		} else {
			reply, err = client.NodeShellSessions(ctx, peer, session, test.after, test.filter)
		}
		if err != nil || reply.NodeShellSessions == nil {
			t.Fatal("actual User shell query", err)
		}
		public, err := json.Marshal(reply)
		if err != nil {
			t.Fatal(err)
		}
		rq15PublicNodeQuery(t, public)
		page := reply.NodeShellSessions
		if page.Total != test.total || len(page.Sessions) != test.count || page.Next != test.next {
			t.Fatal("filtered wire count or cursor", test.filter, page.Total, len(page.Sessions), page.Next)
		}
		if test.filter.State == "open" && test.total == 3 {
			states := map[string]bool{}
			for _, row := range page.Sessions {
				states[row.State] = true
			}
			if !reflect.DeepEqual(states, map[string]bool{"queued": true, "opened": true, "closing": true}) {
				t.Fatal("open filter hid an accepted nonclosed lifetime", states)
			}
		}
		args := []string{"node", "shell-sessions"}
		if test.filter.State != "" {
			args = append(args, "--state", test.filter.State)
		}
		if test.filter.Node != "" {
			args = append(args, "--node", test.filter.Node)
		}
		if test.after != "" {
			args = append(args, "--after", test.after)
		}
		body, code := call(args...)
		var actual control.NodeShellSessionsPage
		if code != 0 || json.Unmarshal(body, &actual) != nil || !reflect.DeepEqual(actual.Sessions, page.Sessions) || actual.Total != page.Total || actual.Next != page.Next || actual.RootRevision != page.RootRevision {
			t.Fatal("actual CLI changed filtered sessions/count/cursor", code)
		}
		rq15PublicNodeQuery(t, body)
	}
	for _, selection := range []control.NodeDrainQuery{{Node: peer.ID}, {Node: peer.ID, Operation: operation}} {
		status, err := client.NodeDrainStatus(ctx, peer, session, selection)
		if err != nil || status.Node != peer.ID || status.Operation != operation || status.State != "Succeeded" || status.Total != 0 || status.Moved != 0 || status.Blocked != 0 {
			t.Fatal("another administrator did not discover the exact original drain", err)
		}
		args := []string{"node", "drain-status", peer.ID}
		if selection.Operation != "" {
			args = append(args, "--operation", selection.Operation)
		}
		body, code := call(args...)
		var actual control.NodeDrainStatus
		if code != 0 || json.Unmarshal(body, &actual) != nil || !reflect.DeepEqual(actual, status) {
			t.Fatal("actual CLI changed the discovered original drain", code)
		}
		rq15PublicNodeQuery(t, body)
	}
	for _, q := range []control.NodeDrainQuery{{Node: "node-b"}, {Node: peer.ID, Operation: "missing-original"}} {
		if _, err := client.NodeDrainStatus(ctx, peer, session, q); err == nil {
			t.Fatal("missing/foreign-node original was fabricated")
		}
	}
	if _, err := client.NodeShellSessions(ctx, peer, session, "", control.NodeShellSessionsQuery{State: "opened"}); err == nil {
		t.Fatal("invalid SDK state filter accepted")
	}
	if _, err := client.query(ctx, peer, session, Request{Method: "node-shell-sessions", State: "opened"}); err == nil {
		t.Fatal("invalid state filter bypassed the actual User handler")
	}
}

func rq15PublicNodeQuery(t *testing.T, raw []byte) {
	t.Helper()
	for _, field := range []string{"Origin", "CloseOrigin", "Signature", "Private", "Reporter", "Credentials", "VerifierRef"} {
		if bytes.Contains(raw, []byte(`"`+field+`"`)) {
			t.Fatal("private original/provider field escaped node query", field)
		}
	}
}

// A private wallet/profile and each protected FD belong only to this fixture.
// The prebuilt CLI is consumed, never compiled/downloaded by a test child.
func rq15NodeQueryCLI(t *testing.T, ctx context.Context, binary, root string, client Client, peer mydcp.Peer, key *identity.Identity) func(...string) ([]byte, int) {
	t.Helper()
	home := filepath.Join(root, "home")
	if err := os.MkdirAll(home, 0700); err != nil {
		t.Fatal(err)
	}
	password := []byte("rq15-private-query-wallet")
	t.Cleanup(func() { clear(password) })
	disk, err := wallet.OpenDisk(home, true)
	if err != nil {
		t.Fatal(err)
	}
	err = disk.Init(password)
	closeErr := disk.Close()
	if err != nil || closeErr != nil {
		t.Fatal("owned query wallet", err, closeErr)
	}
	store, err := OpenCredentials(home, password)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.LoginPrivate(ctx, client, peer, "query.observer", key.Private)
	closeErr = store.Close()
	if err != nil || closeErr != nil {
		t.Fatal("actual separate administrator wallet login", err, closeErr)
	}
	profile := filepath.Join(root, "client.yaml")
	configuration := fmt.Sprintf("version: 1\nauth: user\ncluster: '%x'\npeers:\n - {id: %s, key: '%x', endpoint: '%s', voter: true}\n", client.Cluster, peer.ID, peer.Key, peer.Endpoint)
	if err := os.WriteFile(profile, []byte(configuration), 0600); err != nil {
		t.Fatal(err)
	}
	return func(args ...string) ([]byte, int) {
		t.Helper()
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		if _, err := w.Write(password); err != nil {
			_ = w.Close()
			t.Fatal("owned wallet password FD")
		}
		_ = w.Close()
		flags := []string{"--config", profile, "--user", "query.observer", "--wallet-password-fd", "3", "--no-input"}
		command := exec.CommandContext(ctx, binary, append(flags, args...)...)
		command.Env = append(os.Environ(), "HOME="+home)
		command.ExtraFiles = []*os.File{r}
		var output, diagnostic bytes.Buffer
		command.Stdout, command.Stderr = &output, &diagnostic
		err = command.Run()
		if bytes.Contains(output.Bytes(), password) || bytes.Contains(diagnostic.Bytes(), password) {
			t.Fatal("wallet password escaped actual CLI")
		}
		if err == nil {
			return output.Bytes(), 0
		}
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return output.Bytes(), exit.ExitCode()
		}
		t.Fatal("actual query CLI child did not run", err)
		return nil, -1
	}
}
