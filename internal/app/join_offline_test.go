// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/bootstrap"
	"github.com/jay94ks/mydcd/internal/cluster/membership"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/identity"
)

func TestRealOfflineJoinKeepsOriginalIntentAndCannotInit(t *testing.T) {
	root := t.TempDir()
	source, err := identity.Create(filepath.Join(root, "source-key"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(source.Private)
	target, err := identity.Create(filepath.Join(root, "target-key"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(target.Private)
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
	genesis := config.Peer{ID: "source", Key: source.Actor(), Endpoint: vacant(), Voter: true}
	c := config.Node{Version: 1, Common: config.Common{}, Modules: map[string]config.Module{"network": {}, "workload": {}, "ingress": {}}}
	c.Node.ID, c.Node.Listen = "target", vacant()
	c.Node.StateDir, c.Node.IdentityDir = filepath.Join(root, "target-state"), filepath.Join(root, "target-key")
	inv := membership.Invitation{Schema: 1, Cluster: [32]byte{71}, Admin: [32]byte{72}, Genesis: genesis, Source: genesis, Target: config.Peer{ID: c.Node.ID, Key: target.Actor(), Endpoint: c.Node.Listen}, JoinID: "original-join", ApprovalRevision: 2, MinimumIndex: 4}
	inv.Signature = ed25519.Sign(source.Private, membership.InvitationBytes(inv))
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	if runtime, _, err := Join(ctx, c, inv, inv.Cluster, source.Public); err == nil {
		_ = runtime.Close()
		t.Fatal("offline peer reported joined")
	}
	before, err := bootstrap.Read(c)
	if err != nil || before.Root.Intent != "join" || before.Root.Cluster != inv.Cluster || before.Root.Installed.Index != 0 || before.Ack != nil || before.Root.Operation != inv.JoinID {
		t.Fatal("offline join became initialized/forgot intent", err)
	}
	original, _ := json.Marshal(before)
	if _, err = bootstrap.PrepareInit(c, inv.Admin, "automatic-init"); err == nil {
		t.Fatal("failed Join became standalone")
	}
	foreign := c
	foreign.Node.ID = "other"
	if runtime, err := Open(foreign); err == nil {
		_ = runtime.Close()
		t.Fatal("foreign node identity accepted")
	}
	after, err := bootstrap.Read(c)
	got, _ := json.Marshal(after)
	if err != nil || string(got) != string(original) {
		t.Fatal("refused recovery replaced original intent", err)
	}
	// Opening a node without an explicit init/join record never creates one.
	empty := c
	empty.Node.StateDir = filepath.Join(root, "empty-state")
	if runtime, err := Open(empty); err == nil {
		_ = runtime.Close()
		t.Fatal("empty run bootstrapped implicitly")
	}
	if _, err = os.Stat(empty.Node.StateDir); !os.IsNotExist(err) {
		t.Fatal("empty run created state root", err)
	}
}
