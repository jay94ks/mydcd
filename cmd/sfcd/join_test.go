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
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/app"
	"github.com/jay94ks/seafield/internal/bootstrap"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
)

func TestManagedJoinCLIOriginalAckPinsAndSameRoot(t *testing.T) {
	var help, diag bytes.Buffer
	if code := run([]string{"join", "--help"}, &help, &diag); code != 0 || !bytes.Contains(diag.Bytes(), []byte("source-public-key")) {
		t.Fatal("join help/config independence", code, diag.String())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	root := t.TempDir()
	admin, err := identity.Create(filepath.Join(root, "admin"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(admin.Private)
	vacant := func() string {
		t.Helper()
		p, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		a := p.LocalAddr().String()
		_ = p.Close()
		return a
	}
	c := config.Node{Version: 1, Common: config.Common{}, Modules: map[string]config.Module{"network": {}, "workload": {}, "ingress": {}}}
	c.Node.ID, c.Node.Listen = "source", vacant()
	c.Node.StateDir, c.Node.IdentityDir = filepath.Join(root, "source-state"), filepath.Join(root, "source-key")
	initialized, err := app.Initialize(ctx, c, admin.Public, "init-source")
	if err != nil {
		t.Fatal(err)
	}
	source, err := app.Open(c)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if _, err = source.InstallConfiguration(ctx); err != nil {
		t.Fatal(err)
	}
	ephemeral, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(ephemeral.Private)
	clusterID := initialized.Installation.Root.Cluster
	peer := sfcp.Peer{ID: c.Node.ID, Endpoint: c.Node.Listen, Policy: sfcp.Policy{Key: sfcp.Identity(source.Identity.Public), Respond: true}}
	mesh, err := sfcp.NewTransport(ephemeral, clusterID, func(key sfcp.Identity) (sfcp.Peer, bool) { return peer, key == peer.Key })
	if err != nil {
		t.Fatal(err)
	}
	defer mesh.Close()
	client := userauth.Client{Mesh: mesh, Self: ephemeral, Cluster: clusterID, Peers: []sfcp.Peer{peer}}
	enroll, err := client.Enroll(ctx, peer, control.Enrollment{Schema: 1, RequestID: "enroll-source", User: access.User{ID: "admin", Username: "admin", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: admin.Public, Enabled: true}}}}, admin.Private)
	if err != nil || enroll.Result == nil || enroll.Result.Code != state.Applied {
		t.Fatal("enroll", err)
	}
	session, err := client.Login(ctx, peer, "admin", admin.Private)
	if err != nil {
		t.Fatal(err)
	}
	targetKey, err := identity.Create(filepath.Join(root, "target-key"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(targetKey.Private)
	target := config.Peer{ID: "target", Key: targetKey.Actor(), Endpoint: vacant()}
	raw, _ := control.ChangeBytes("invite-node", "admin", 0, control.NodeInvitation{Peer: target, JoinID: "join-target"})
	var ch control.Change
	_ = json.Unmarshal(raw, &ch)
	op, err := client.Prepare(ctx, peer, session, "invite-target", ch)
	if err != nil {
		t.Fatal(err)
	}
	approved, err := client.Operation(ctx, peer, op, false)
	if err != nil || approved.Result == nil || approved.Result.Code != state.Applied {
		t.Fatal("invite", err)
	}
	inv, err := client.NodeInvitation(ctx, peer, session, target.ID)
	if err != nil {
		t.Fatal(err)
	}
	invFile, nodeFile := filepath.Join(root, "invitation.json"), filepath.Join(root, "target.yaml")
	invitation, _ := inv.Encode()
	if err = os.WriteFile(invFile, invitation, 0600); err != nil {
		t.Fatal(err)
	}
	nodeText := fmt.Sprintf("version: 1\nnode:\n  id: target\n  state_dir: target-state\n  identity_dir: target-key\n  listen: '%s'\nmodules:\n  network: {enabled: false}\n  workload: {enabled: false}\n  ingress: {enabled: false}\n", target.Endpoint)
	if err = os.WriteFile(nodeFile, []byte(nodeText), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadNode(nodeFile)
	if err != nil {
		t.Fatal(err)
	}
	invoke := func(pin string, want int) string {
		t.Helper()
		var out, diagnostic bytes.Buffer
		code := run([]string{"--config", nodeFile, "join", "--cluster", fmt.Sprintf("%x", clusterID), "--source-public-key", pin, "--invitation", invFile}, &out, &diagnostic)
		if code != want {
			t.Fatal("join CLI", code, want, out.String(), diagnostic.String())
		}
		return out.String()
	}
	invoke(fmt.Sprintf("%064x", 999), 2)
	if _, err = os.Stat(cfg.Node.StateDir); !os.IsNotExist(err) {
		t.Fatal("bad pin changed target root", err)
	}
	// User-purpose credentials must not start another node's join operation.
	if _, err = app.CallMembership(ctx, mesh, peer, app.MemberRequest{Method: "join", Node: target.ID, JoinID: inv.JoinID}); err == nil {
		t.Fatal("user transport gained node membership purpose")
	}
	output := invoke(source.Identity.Actor(), 0)
	var result struct {
		Status             string
		Voter              bool
		Quorum             int
		ConfigurationIndex uint64 `json:"configuration_index"`
	}
	if json.Unmarshal([]byte(output), &result) != nil || result.Status != "Joined" || result.Voter || result.Quorum != 1 || result.ConfigurationIndex == 0 {
		t.Fatal("join output", output)
	}
	before, err := bootstrap.Read(cfg)
	if err != nil || before.Ack == nil {
		t.Fatal("original local ACK missing", err)
	}
	view, err := source.Engine().Read(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	index := view.State.Index()
	beforeObjects := view.State.Objects("")
	invoke(source.Identity.Actor(), 0)
	after, err := bootstrap.Read(cfg)
	if err != nil || !reflect.DeepEqual(before.Ack, after.Ack) || before.Root.Cluster != after.Root.Cluster || before.Root.Self != after.Root.Self {
		t.Fatal("repeat CLI replaced identity/ACK", err)
	}
	view, err = source.Engine().Read(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	// The repeated CLI must write nothing. Members register their default
	// storage root in the background after joining (#684), so those writes
	// may land in between and are not the CLI's.
	for key, o := range view.State.Objects("") {
		if b := beforeObjects[key]; (b.Revision != o.Revision || b.Present != o.Present) && key != control.NodeStorageKey && !strings.HasPrefix(key, control.NodeStorageKey+"/") {
			t.Fatal("repeat CLI repeated metadata effects", key)
		}
	}
	foreign := inv
	foreign.JoinID = "different-join"
	if _, err = bootstrap.PrepareJoin(cfg, foreign, clusterID, source.Identity.Public); err == nil {
		t.Fatal("changed original invitation accepted")
	}
	// A second real target loses the first install-ACK reply AFTER the shared
	// FSM confirms it. Its local durable ACK must survive explicit CLI resume.
	lostKey, err := identity.Create(filepath.Join(root, "lost-key"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(lostKey.Private)
	lost := config.Peer{ID: "lost-target", Key: lostKey.Actor(), Endpoint: vacant()}
	raw, _ = control.ChangeBytes("invite-node", "admin", 0, control.NodeInvitation{Peer: lost, JoinID: "join-lost"})
	_ = json.Unmarshal(raw, &ch)
	op, err = client.Prepare(ctx, peer, session, "invite-lost", ch)
	if err != nil {
		t.Fatal(err)
	}
	approved, err = client.Operation(ctx, peer, op, false)
	if err != nil || approved.Result == nil || approved.Result.Code != state.Applied {
		t.Fatal("lost target approval", err)
	}
	lostInv, err := client.NodeInvitation(ctx, peer, session, lost.ID)
	if err != nil {
		t.Fatal(err)
	}
	invFile, nodeFile = filepath.Join(root, "lost-invitation.json"), filepath.Join(root, "lost.yaml")
	invitation, _ = lostInv.Encode()
	if err = os.WriteFile(invFile, invitation, 0600); err != nil {
		t.Fatal(err)
	}
	lostText := strings.NewReplacer("id: target", "id: lost-target", "target-state", "lost-state", "target-key", "lost-key", target.Endpoint, lost.Endpoint).Replace(nodeText)
	if err = os.WriteFile(nodeFile, []byte(lostText), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err = config.LoadNode(nodeFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = bootstrap.PrepareJoin(cfg, lostInv, clusterID, source.Identity.Public); err != nil {
		t.Fatal(err)
	}
	partial, err := app.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if partial != nil {
			_ = partial.Close()
		}
	}()
	if _, err = app.CallMembership(ctx, partial.Mesh, peer, app.MemberRequest{Method: "join", Node: lost.ID, JoinID: lostInv.JoinID}); err != nil {
		t.Fatal(err)
	}
	if _, err = partial.InstallConfiguration(ctx); err != nil {
		t.Fatal(err)
	}
	original, err := bootstrap.PrepareAck(cfg)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := partial.Mesh.Dial(ctx, peer)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := conn.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(app.MemberRequest{Schema: 1, Method: "install", Node: lost.ID, JoinID: lostInv.JoinID, Ack: original.Ack})
	digest := sha256.Sum256(body)
	if err = sfcp.WriteFrame(stream, sfcp.Frame{Purpose: sfcp.Membership, Kind: 1, Request: partial.Mesh.NextRequest(), Fields: []sfcp.Field{{Tag: 1, Required: true, Value: body}, {Tag: 2, Required: true, Value: digest[:]}}}); err != nil {
		t.Fatal(err)
	}
	policy := control.Policy{Cluster: clusterID, BootstrapKey: admin.Public, TrustRoot: source.Identity.Public, Genesis: initialized.Installation.Genesis}
	tick := time.NewTicker(20 * time.Millisecond)
	for {
		current, err := source.Engine().Read(ctx, true)
		if err != nil {
			t.Fatal(err)
		}
		directory, err := policy.Members(current.State)
		if err != nil {
			t.Fatal(err)
		}
		entry, ok := directory.Entry(lost.ID)
		if ok && entry.Phase == "ready" {
			index = current.State.Index()
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("ACK not committed", ctx.Err())
		case <-tick.C:
		}
	}
	tick.Stop()
	stream.CancelRead(1)
	_ = stream.Close() // The caller never reads the ACK reply.
	if err = partial.Close(); err != nil {
		t.Fatal(err)
	}
	partial = nil
	invoke(source.Identity.Actor(), 0)
	recovered, err := bootstrap.Read(cfg)
	if err != nil || !reflect.DeepEqual(original.Ack, recovered.Ack) {
		t.Fatal("unobserved ACK reply replaced original proof", err)
	}
	view, err = source.Engine().Read(ctx, true)
	if err != nil || view.State.Index() != index {
		t.Fatal("lost ACK resume repeated effect", err)
	}
	t.Log("actual install ACK committed but its reply was unread/cancelled; same DB/original ACK and CLI resume produced zero new shared effects")
	t.Log("real CLI joins once as nonvoter, keeps original pinned intent/ACK across repeat, denies user transport and wrong source pin")
}
