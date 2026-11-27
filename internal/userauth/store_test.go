// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
)

func TestPrivateSessionStoreAtomicPermissionsProfileAndSymlink(t *testing.T) {
	issuer, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	self, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(issuer.Private)
	defer clear(self.Private)
	c := Client{Self: self, Cluster: [32]byte{83}, Peers: []sfcp.Peer{{ID: "node", Endpoint: "127.0.0.1:7443", Policy: sfcp.Policy{Key: sfcp.Identity(issuer.Public), Respond: true}}}}
	now := time.Now().Unix()
	s := access.Session{Schema: 1, ID: "session", Cluster: c.Cluster, User: "alice", Credential: "key", AccountRevision: 1, Key: self.Public, Issuer: issuer.Public, IssuerEpoch: 1, IssuedAt: now, ExpiresAt: now + 3600, Scopes: []access.Scope{{Tenant: "*", Actions: []access.Action{access.Read}}}}
	s.Signature = ed25519.Sign(issuer.Private, access.SessionBytes(s))
	home := t.TempDir()
	if err = Save(home, c, s, ""); err != nil {
		t.Fatal(err)
	}
	stored, err := Load(home, c)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(stored.Self.Private)
	if stored.Self.Public != self.Public || stored.Session.ID != s.ID || !bytes.Equal(stored.Self.Private, self.Private) {
		t.Fatal("original proof key/session changed")
	}
	if _, err = json.Marshal(stored); err == nil || fmt.Sprintf("%+v", stored) != "[redacted user session]" {
		t.Fatal("private session formatting was not redacted")
	}
	if err = Save(home, c, s, "one"); err != nil {
		t.Fatal(err)
	}
	updated, err := Load(home, c)
	if err != nil || updated.Tenant != "one" {
		t.Fatal(updated.Tenant, err)
	}
	defer clear(updated.Self.Private)
	profile := c.Profile()
	path := filepath.Join(home, ".sfc", "sessions", hex.EncodeToString(c.Cluster[:]), "profiles", hex.EncodeToString(profile[:]), "session.json")
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("private session permissions", err)
	}
	wrong := c
	wrong.Peers = append([]sfcp.Peer(nil), c.Peers...)
	wrong.Peers[0].Endpoint = "127.0.0.1:7444"
	if moved, err := Load(home, wrong); err != nil {
		t.Fatal("a moved endpoint lost the cluster's session", err)
	} else {
		clear(moved.Self.Private)
	}
	wrong.Cluster[0] ^= 1
	if _, err = Load(home, wrong); err == nil {
		t.Fatal("another cluster reused session")
	}
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = Load(home, c); err == nil {
		t.Fatal("public session file accepted")
	}
	if err = os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(path, path+".good"); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(path+".good", path); err != nil {
		t.Fatal(err)
	}
	if _, err = Load(home, c); err == nil {
		t.Fatal("symlink session file accepted")
	}
	if err = Save(home, c, s, ""); err == nil {
		t.Fatal("save replaced an unknown symlink")
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(path+".good", path); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(path)
	if err = os.Rename(dir, dir+".good"); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(dir+".good", dir); err != nil {
		t.Fatal(err)
	}
	if _, err = Load(home, c); err == nil {
		t.Fatal("symlink session directory accepted")
	}
}
