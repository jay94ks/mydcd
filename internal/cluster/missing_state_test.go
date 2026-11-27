// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/storage"
)

func TestRealMissingRaftStateNeverReinitializesDurableFSM(t *testing.T) {
	f := newControlBoundary(t)
	f.call(f.command("enroll-missing-log", "enroll", "", 0, access.User{ID: "admin", Username: "operator", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: f.client.Public, Enabled: true}}}))
	original, err := f.engine.db.Get("fsm")
	if err != nil {
		t.Fatal(err)
	}
	f.close()
	if err = os.Remove(filepath.Join(f.options.Root, "control", "raft.db")); err != nil {
		t.Fatal(err)
	}
	f.server, err = sfcp.NewTransport(f.node, f.policy.Cluster, f.lookup)
	if err != nil {
		t.Fatal(err)
	}
	peer, _ := f.lookup(sfcp.Identity(f.node.Public))
	if err = f.server.Listen(peer.Endpoint); err != nil {
		t.Fatal(err)
	}
	f.options.Mesh = f.server
	engine, err := Open(f.options)
	if err == nil {
		_ = engine.Close()
		t.Fatal("missing Raft state recreated over committed FSM")
	}
	if !strings.Contains(err.Error(), "Raft state is missing") {
		t.Fatal("wrong failure boundary", err)
	}
	db, err := storage.Open(filepath.Join(f.options.Root, "control", "fsm.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	current, err := db.Get("fsm")
	if err != nil || !bytes.Equal(current, original) {
		t.Fatal("committed account/checkpoint changed after refused recovery", err)
	}
}
