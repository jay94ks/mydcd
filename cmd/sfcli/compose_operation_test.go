// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/app"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
)

func TestComposeOperationStatusOptions(t *testing.T) {
	for _, args := range [][]string{{"status", "-p", "app", "--operation", "original"}, {"status", "-p", "app"}} {
		if _, err := parseComposeOptions(args, &bytes.Buffer{}); err != nil {
			t.Fatal(args, err)
		}
	}
	for _, args := range [][]string{{"status", "--operation", "original"}, {"status", "-p", "app", "--operation", ""}, {"status", "-p", "app", "--plan", "plan.json"}, {"ps", "--operation", "original"}} {
		if _, err := parseComposeOptions(args, &bytes.Buffer{}); err == nil {
			t.Fatal("invalid operation selector", args)
		}
	}
}

// Actual authentication/SFCP/Raft/DB/CLI; no native owner or Ready fixtures.
func TestRealComposeOperationQueryRetiredSuccessorAndQuorumRecovery(t *testing.T) {
	testRealComposeAppBoundary(t, true, true, "operations")
}

func TestRealComposeHistoricalUnconfirmedAcceptIsResultOnly(t *testing.T) {
	testRealComposeAppBoundary(t, true, true, "operation-reply")
}

func privateComposeAcceptPath(t *testing.T, home, id string) string {
	t.Helper()
	name := fmt.Sprintf("%x.json", sha256.Sum256([]byte("compose/"+id+"/accept")))
	found := ""
	if err := filepath.WalkDir(home, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && entry.Name() == name {
			if found != "" {
				return fmt.Errorf("duplicate accept fixture")
			}
			found = path
		}
		return nil
	}); err != nil || found == "" {
		t.Fatal("original private accept location", err)
	}
	return found
}

func verifyComposeHistoricalUnconfirmedAccept(t *testing.T, home string, call func(int, ...string) []byte, c *userauth.Client, session access.Session, view func() state.State) {
	t.Helper()
	path := privateComposeAcceptPath(t, home, "rollout")
	confirmed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.WriteFile(path, confirmed, 0600); err != nil {
			t.Error(err)
		}
	}()
	// Inject loss of the CLIENT's confirmed result only. The real shared app is
	// already Retired in its original DB; no Ready/owner observation is forged.
	type diskRecord userauth.OperationRecord
	var disk diskRecord
	if json.Unmarshal(confirmed, &disk) != nil || disk.Result == nil {
		t.Fatal("confirmed accept fixture")
	}
	originalBytes, signature, result := control.OperationBytes(disk.Operation), bytes.Clone(disk.Operation.Signature), *disk.Result
	disk.Result = nil
	raw, err := json.Marshal(disk)
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{"up", "resume"} {
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		before := view().Index()
		var out struct {
			Status   string                   `json:"status"`
			Original control.AppOperationView `json:"original"`
		}
		if json.Unmarshal(call(0, "compose", method, "--tenant", "tenant", "--operation", "rollout", "--no-input", "--group-password-fd", "tenant/unrequired=999999"), &out) != nil || out.Status != "original-result" || !out.Original.Found || out.Original.Current || out.Original.Operation.Status != "Retired" {
			t.Fatal("historical unconfirmed accept", method, out)
		}
		retained, err := userauth.LoadOperation(home, *c, session, "compose/rollout/accept")
		if err != nil || retained.Result == nil || *retained.Result != result || !bytes.Equal(control.OperationBytes(retained.Operation), originalBytes) || !bytes.Equal(retained.Operation.Signature, signature) {
			t.Fatal("result recovery replaced original", err)
		}
		if view().Index() != before {
			t.Fatal("historical result recovery committed a new effect")
		}
	}
	t.Log("actual original accept result query recovers deliberately absent local receipt after real retirement/Snapshot/same DB; up and resume preserve original signed command/result without approval/provider access or new shared commits; no wire-disconnect or native claim")
}

func verifyComposeOperationCLI(t *testing.T, ctx context.Context, home, root string, call func(int, ...string) []byte, login func(), c *userauth.Client, session access.Session, source sfcp.Peer, policy control.Policy, view func() state.State, runtime *app.Runtime) {
	t.Helper()
	selection := control.AppOperationRequest{App: "app", ID: "rollout"}
	intent, err := userauth.LoadCompose(home, *c, session, "rollout")
	if err != nil {
		t.Fatal(err)
	}
	accept, err := userauth.LoadOperation(home, *c, session, "compose/rollout/accept")
	if err != nil {
		t.Fatal(err)
	}
	originalBytes, originalSignature := control.OperationBytes(accept.Operation), bytes.Clone(accept.Operation.Signature)
	query := func(current access.Session) control.AppOperationView {
		t.Helper()
		reply, err := c.AppOperation(ctx, source, current, "tenant", selection)
		if err != nil || reply.AppOperation == nil {
			t.Fatal("exact query", err)
		}
		return *reply.AppOperation
	}
	original := query(session)
	if !original.Found || original.Current || original.Operation.Status != "Retired" || original.Operation.Plan != intent.Digest || original.Operation.Epoch != intent.Epoch {
		t.Fatal("retired exact original", original)
	}
	checkCLI := func() {
		t.Helper()
		before := view().Index()
		var status struct {
			Status    string                   `json:"status"`
			Operation control.AppOperationView `json:"operation"`
		}
		if json.Unmarshal(call(0, "compose", "status", "--tenant", "tenant", "-p", "app", "--operation", "rollout"), &status) != nil || status.Status != "original-result" || !reflect.DeepEqual(status.Operation.Operation, original.Operation) || status.Operation.Current {
			t.Fatal("CLI exact history", status)
		}
		for _, method := range []string{"up", "resume"} {
			var out struct {
				Status   string                   `json:"status"`
				Original control.AppOperationView `json:"original"`
			}
			// An unused password FD proves the historical branch never attempts
			// a new approval/provider read or requires a surviving Compose file.
			if json.Unmarshal(call(0, "compose", method, "--tenant", "tenant", "--operation", "rollout", "--no-input", "--group-password-fd", "tenant/unrequired=999999"), &out) != nil || out.Status != "original-result" || !reflect.DeepEqual(out.Original.Operation, original.Operation) {
				t.Fatal("original result-only resume", method, out)
			}
		}
		var absent struct {
			Status string `json:"status"`
		}
		if json.Unmarshal(call(4, "compose", "status", "--tenant", "tenant", "-p", "app", "--operation", "not-known"), &absent) != nil || absent.Status != "unknown" {
			t.Fatal("missing history is Unknown", absent)
		}
		if view().Index() != before {
			t.Fatal("original query/resume mutated committed state")
		}
	}
	checkCLI()
	// Losing the local original accept is not permission to sign a new one.
	acceptPath := privateComposeAcceptPath(t, home, "rollout")
	if err := os.Rename(acceptPath, acceptPath+".held"); err != nil {
		t.Fatal(err)
	}
	func() {
		defer func() {
			if err := os.Rename(acceptPath+".held", acceptPath); err != nil {
				t.Error(err)
			}
		}()
		before := view().Index()
		for _, method := range []string{"up", "resume"} {
			call(4, "compose", method, "--tenant", "tenant", "--operation", "rollout", "--no-input")
		}
		if _, err := os.Stat(acceptPath); !os.IsNotExist(err) {
			t.Fatal("missing original accept was recreated", err)
		}
		if view().Index() != before {
			t.Fatal("missing accept caused a replacement mutation")
		}
		call(0, "compose", "status", "--tenant", "tenant", "-p", "app", "--operation", "rollout")
	}()
	t.Run("status-without-local-intent", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		invoke, _ := fixtureWallet(t, home)
		freshCall := func(args ...string) {
			t.Helper()
			var out, diagnostic bytes.Buffer
			if code := invoke(append([]string{"--config", filepath.Join(root, "client.yaml")}, args...), &out, &diagnostic); code != 0 {
				t.Fatal("fresh wallet CLI", args, code, diagnostic.String())
			}
		}
		freshCall("login", "--username", "admin", "--method", "private-key", "--key-file", filepath.Join(root, "admin", "key.pem"))
		freshCall("compose", "status", "--tenant", "tenant", "-p", "app", "--operation", "rollout")
	})
	// A new accepted operation replaces only the active entry, not old results.
	file := filepath.Join(root, "next-compose.yaml")
	if err = os.WriteFile(file, appComposeDocument(1), 0600); err != nil {
		t.Fatal(err)
	}
	call(0, "compose", "up", "--tenant", "tenant", "--operation", "successor", "-f", file)
	checkCLI()
	if got := query(session); !reflect.DeepEqual(got.Operation, original.Operation) || got.Current {
		t.Fatal("successor replaced historical result", got)
	}
	apply := func(id, action string, expected uint64, payload any) {
		t.Helper()
		raw, err := control.ChangeBytes(action, session.User, expected, payload)
		if err != nil {
			t.Fatal(err)
		}
		var change control.Change
		_ = json.Unmarshal(raw, &change)
		op, err := c.Prepare(ctx, source, session, id, change)
		if err != nil {
			t.Fatal(err)
		}
		reply, err := c.Operation(ctx, source, op, false)
		if err != nil || reply.Result == nil || reply.Result.Code != state.Applied {
			t.Fatal(action, reply.Result, err)
		}
	}
	reader, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(reader.Private)
	apply("operation-reader", "put-user", 0, access.User{ID: "reader", Username: "reader", Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: reader.Public, Enabled: true}}})
	apply("operation-reader-member", "set-membership", 0, access.Membership{Tenant: "tenant", User: "reader", Role: access.Viewer, Enabled: true})
	readSession, err := c.Login(ctx, source, "reader", reader.Private)
	if err != nil {
		t.Fatal(err)
	}
	if got := query(readSession); !reflect.DeepEqual(got.Operation, original.Operation) {
		t.Fatal("current reader permission", got)
	}
	if _, err = c.AppOperation(ctx, source, readSession, "foreign", selection); err == nil {
		t.Fatal("cross-tenant query allowed")
	}
	if _, err = c.Query(ctx, source, session, "app-operation", "tenant"); err == nil {
		t.Fatal("missing typed selector accepted")
	}
	catalog, err := policy.Catalog(view())
	if err != nil {
		t.Fatal(err)
	}
	m, _ := catalog.Membership("tenant", "reader")
	m.Enabled, m.Revision = false, 0
	old, _ := catalog.Membership("tenant", "reader")
	apply("operation-reader-revoke", "set-membership", old.Revision, m)
	if _, err = c.AppOperation(ctx, source, readSession, "tenant", selection); err == nil {
		t.Fatal("revoked membership disclosed old result")
	}

	// This second Runtime has no native modules. Close/reopen its exact DB/key;
	// never shrink the N2 voter configuration to make a minority available.
	probe, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := probe.LocalAddr().String()
	_ = probe.Close()
	cfg := config.Node{Version: 1, Common: config.Common{}, Modules: map[string]config.Module{"network": {}, "workload": {}, "ingress": {}}}
	cfg.Node.ID, cfg.Node.Listen = "node-b", address
	cfg.Node.StateDir, cfg.Node.IdentityDir = filepath.Join(root, "voter-b-state"), filepath.Join(root, "voter-b-key")
	key, err := identity.Create(cfg.Node.IdentityDir)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key.Private)
	apply("operation-invite-b", "invite-node", 0, control.NodeInvitation{Peer: config.Peer{ID: "node-b", Key: key.Actor(), Endpoint: address}, JoinID: "operation-join-b"})
	inv, err := c.NodeInvitation(ctx, source, session, "node-b")
	if err != nil {
		t.Fatal(err)
	}
	b, record, err := app.Join(ctx, cfg, inv, c.Cluster, runtime.Identity.Public)
	if err != nil {
		t.Fatal("join N2 candidate", err)
	}
	defer func() {
		if b != nil {
			if err := b.Close(); err != nil {
				t.Error(err)
			}
		}
	}()
	wait := func(label string, predicate func() bool) {
		t.Helper()
		for !predicate() {
			select {
			case <-ctx.Done():
				t.Fatal(label, ctx.Err())
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	wait("joined learner ready", func() bool {
		d, e := policy.Members(view())
		entry, found := d.Entry("node-b")
		return e == nil && found && entry.Phase == membership.Ready
	})
	directory, _ := policy.Members(view())
	entry, _ := directory.Entry("node-b")
	apply("operation-promote-b", "promote-node", entry.Revision, control.NodeSelection{ID: "node-b"})
	wait("N2 Q2 committed voters", func() bool {
		d, e := policy.Members(view())
		entry, found := d.Entry("node-b")
		return e == nil && found && entry.Phase == membership.Active && entry.Peer.Voter
	})
	installed, err := runtime.Engine().InstalledConfiguration(ctx, true)
	voters := 0
	for _, server := range installed.Configuration.Servers {
		if server.Suffrage == raft.Voter {
			voters++
		}
	}
	if err != nil || voters != 2 {
		t.Fatal("actual SDK voter count", voters, err)
	}
	apply("operation-n2-change", "create-tenant", 0, control.TenantID{ID: "n-two"})
	// Freeze ONE signed change before losing quorum. Unknown must preserve it.
	raw, _ := control.ChangeBytes("create-tenant", session.User, 0, control.TenantID{ID: "after-restore"})
	var change control.Change
	_ = json.Unmarshal(raw, &change)
	pending, err := c.Prepare(ctx, source, session, "operation-after-restore", change)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = userauth.StageOperation(home, *c, pending); err != nil {
		t.Fatal(err)
	}
	if err = b.Engine().Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	if err = b.Close(); err != nil {
		t.Fatal(err)
	}
	b = nil
	readCtx, stop := context.WithTimeout(ctx, 2*time.Second)
	_, err = c.AppOperation(readCtx, source, session, "tenant", selection)
	stop()
	if err == nil {
		t.Fatal("minority returned a fresh quorum query")
	}
	beforeLocal, err := runtime.Engine().Read(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	call(4, "--timeout", "2s", "manage", "resume", "--request-id", pending.RequestID)
	afterLocal, err := runtime.Engine().Read(ctx, false)
	if err != nil || afterLocal.State.Index() != beforeLocal.State.Index() {
		t.Fatal("minority committed a management change", err)
	}
	retained, err := userauth.LoadOperation(home, *c, session, pending.RequestID)
	if err != nil || retained.Result != nil || !bytes.Equal(control.OperationBytes(retained.Operation), control.OperationBytes(pending)) || !bytes.Equal(retained.Operation.Signature, pending.Signature) {
		t.Fatal("minority lost original Unknown", err)
	}
	b, err = app.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Either voter may win the election after the restart, and a latest read
	// succeeds only on the leader. The rest of the test reads node-a's view,
	// so once quorum is back, hand leadership back to node-a if node-b won.
	latest := func(r *app.Runtime) bool {
		readCtx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
		defer cancel()
		_, err := r.Engine().Read(readCtx, true)
		return err == nil
	}
	wait("same voter DB current quorum", func() bool { return latest(runtime) || latest(b) })
	if !runtime.Engine().IsLeader() {
		if err = b.Engine().TransferLeadership(ctx, "node-a", runtime.Mesh.Addr().String()); err != nil {
			t.Fatal("leadership back to node-a", err)
		}
		wait("node-a leads again", func() bool { return latest(runtime) })
	}
	resumed, err := b.ResumeInstallation(ctx)
	if err != nil || b.Identity.Public != key.Public || !reflect.DeepEqual(resumed.Ack, record.Ack) {
		t.Fatal("same voter identity/ACK", err)
	}
	call(0, "manage", "resume", "--request-id", pending.RequestID)
	retained, err = userauth.LoadOperation(home, *c, session, pending.RequestID)
	if err != nil || retained.Result == nil || retained.Result.Code != state.Applied || !bytes.Equal(control.OperationBytes(retained.Operation), control.OperationBytes(pending)) || !bytes.Equal(retained.Operation.Signature, pending.Signature) {
		t.Fatal("restore replaced original pending change", err)
	}
	checkCLI()
	afterAccept, err := userauth.LoadOperation(home, *c, session, "compose/rollout/accept")
	if err != nil || !bytes.Equal(control.OperationBytes(afterAccept.Operation), originalBytes) || !bytes.Equal(afterAccept.Operation.Signature, originalSignature) {
		t.Fatal("historical resume replaced original accept", err)
	}
	t.Log("actual typed User/SFCP operation lookup: current Planned then exact Retired after Snapshot/same DB; no-local-intent status; successor preserves old result; historical up/resume has no state/approval/provider effects; viewer/current membership revoke/cross-tenant/selector deny; actual N2/Q2 management, minority query/change refusal retaining one signed Unknown, exact voter DB/identity/ACK restore and original explicit resume. Native modules disabled; no native or HA claim.")
}
