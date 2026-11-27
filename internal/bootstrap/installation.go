// SPDX-License-Identifier: Apache-2.0

// Package bootstrap persists the original installation intent. Shared cluster
// authority stays in Raft; this local record never substitutes for consensus.
package bootstrap

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/storage"
)

var ErrInstallation = errors.New("invalid, missing or conflicting explicit node installation")

const filename = "installation.db"

type Record struct {
	Schema    uint8
	Root      lifecycle.Root
	Admin     [32]byte
	Endpoint  string
	Genesis   config.Peer
	Signature []byte
	Join      *membership.Invitation `json:",omitempty"`
	Ack       *membership.Ack        `json:",omitempty"`
	// Listen is node.yaml's listen address after the server moved
	// (`sfcd set-listen`); Endpoint stays the address it was installed with,
	// which the genesis and the invitation bind.
	Listen string `json:",omitempty"`
}

// CurrentListen is the listen address node.yaml must have.
func (r Record) CurrentListen() string {
	if r.Listen != "" {
		return r.Listen
	}
	return r.Endpoint
}

func signingBytes(r Record) []byte {
	r.Signature = nil
	b, _ := json.Marshal(r)
	return append([]byte("sfc-installation-1\x00"), b...)
}
func (r Record) Validate() error {
	key, err := identity.ParseKey(r.Genesis.Key)
	if r.Schema != 1 || r.Root.Validate() != nil || r.Admin == ([32]byte{}) || err != nil || key != r.Root.TrustRoot || !r.Genesis.Voter || !lifecycle.ValidID(r.Genesis.ID) || config.ValidateCanonicalEndpoint(r.Genesis.Endpoint) != nil || config.ValidateCanonicalEndpoint(r.Endpoint) != nil || !ed25519.Verify(ed25519.PublicKey(r.Root.Self.Key[:]), signingBytes(r), r.Signature) {
		return ErrInstallation
	}
	if r.Listen != "" && (r.Listen == r.Endpoint || config.ValidateCanonicalEndpoint(r.Listen) != nil) {
		return ErrInstallation
	}
	if r.Root.Intent == lifecycle.RestoreIntent {
		// A new server rebuilt the cluster from a backup: the genesis is the
		// original one (it binds the stored records), not this server.
		if r.Join != nil || r.Ack != nil || r.Genesis.ID == r.Root.Self.ID || key == r.Root.Self.Key {
			return ErrInstallation
		}
	} else if r.Root.Intent == lifecycle.Init {
		if r.Join != nil || r.Ack != nil || r.Genesis.ID != r.Root.Self.ID || r.Genesis.Endpoint != r.Endpoint {
			return ErrInstallation
		}
	} else {
		if r.Join == nil || r.Join.Verify(r.Root.Cluster, mustKey(r.Join.Source.Key)) != nil || r.Join.Genesis != r.Genesis || r.Join.Admin != r.Admin || r.Join.Target.ID != r.Root.Self.ID || mustKey(r.Join.Target.Key) != r.Root.OriginalKey() || r.Join.Target.Endpoint != r.Endpoint || r.Join.JoinID != r.Root.Operation {
			return ErrInstallation
		}
		if a := r.Ack; a != nil {
			if a.Schema != 1 || a.Cluster != r.Root.Cluster || a.Node != r.Root.Self.ID || a.Key != r.Root.OriginalKey() || a.JoinID != r.Root.Operation || a.ConfigurationIndex == 0 || a.ConfigurationIndex > r.Root.Installed.Index || a.AppliedIndex < a.ConfigurationIndex || a.AppliedIndex > r.Root.AppliedIndex || !ed25519.Verify(ed25519.PublicKey(a.Key[:]), membership.AckBytes(*a), a.Signature) {
				return ErrInstallation
			}
		}
	}
	return nil
}

func private(info os.FileInfo, directory bool) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uint32(os.Geteuid()) && info.Mode().Perm()&0077 == 0 && (directory && info.IsDir() || !directory && info.Mode().IsRegular())
}

func checkManaged(c config.Node) error {
	if c.Version != 1 || len(c.Common.Peers) != 0 || c.Node.StateDir == "" || c.Node.IdentityDir == "" || config.ValidateCanonicalEndpoint(c.Node.Listen) != nil || !lifecycle.ValidID(c.Node.ID) {
		return ErrInstallation
	}
	for name, m := range c.Modules {
		if m.Enabled && name != "network" && name != "workload" && name != "ingress" {
			return errors.New("unknown managed native module")
		}
	}
	return nil
}

func Read(c config.Node) (Record, error) {
	r, err := readRecord(c)
	if err == nil && c.Node.Listen != r.CurrentListen() {
		return Record{}, fmt.Errorf("%w: node.yaml listen %s is not this server's address %s; after the server moved, run 'sfcd set-listen'", ErrInstallation, c.Node.Listen, r.CurrentListen())
	}
	return r, err
}

func readRecord(c config.Node) (Record, error) {
	if checkManaged(c) != nil {
		return Record{}, ErrInstallation
	}
	info, err := os.Lstat(c.Node.StateDir)
	if err != nil || !private(info, true) {
		return Record{}, ErrInstallation
	}
	info, err = os.Lstat(filepath.Join(c.Node.StateDir, filename))
	if err != nil || !private(info, false) {
		return Record{}, ErrInstallation
	}
	db, err := storage.Open(filepath.Join(c.Node.StateDir, filename))
	if err != nil {
		return Record{}, err
	}
	defer db.Close()
	raw, err := db.Get("installation")
	if err != nil || len(raw) > 1<<20 {
		return Record{}, ErrInstallation
	}
	var r Record
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF || r.Validate() != nil {
		return Record{}, ErrInstallation
	}
	canonical, _ := json.Marshal(r)
	if !bytes.Equal(raw, canonical) {
		return Record{}, ErrInstallation
	}
	self, err := identity.Load(IdentityPath(c, r))
	if err != nil {
		return Record{}, err
	}
	defer clear(self.Private)
	if r.Root.Resume(r.Root.Cluster, lifecycle.Member{ID: c.Node.ID, Key: self.Public}) != nil {
		return Record{}, ErrInstallation
	}
	if c.Common.Cluster != "" && c.Common.Cluster != hex.EncodeToString(r.Root.Cluster[:]) || c.Common.Admin != "" && c.Common.Admin != hex.EncodeToString(r.Admin[:]) {
		return Record{}, ErrInstallation
	}
	if r.Root.Installed.Index != 0 {
		for _, name := range []string{"raft.db", "fsm.db"} {
			info, err = os.Lstat(filepath.Join(c.Node.StateDir, "control", name))
			if err != nil || !private(info, false) {
				return Record{}, errors.New("installed control state is missing; refusing reinitialization")
			}
		}
	}
	return r, nil
}

func Effective(c config.Node) (config.Node, Record, error) {
	r, err := Read(c)
	if err != nil {
		return c, r, err
	}
	c.Common.Cluster, c.Common.Admin = hex.EncodeToString(r.Root.Cluster[:]), hex.EncodeToString(r.Admin[:])
	c.Common.Peers = []config.Peer{r.Genesis}
	if r.Root.Intent == lifecycle.RestoreIntent {
		// The original genesis is gone; this server is the only voter.
		c.Common.Peers = []config.Peer{{ID: r.Root.Self.ID, Key: identityHex(r.Root.Self.Key), Endpoint: r.Endpoint, Voter: true}}
	}
	if r.Join != nil {
		if r.Join.Source.ID != r.Genesis.ID {
			c.Common.Peers = append(c.Common.Peers, r.Join.Source)
		}
		c.Common.Peers = append(c.Common.Peers, r.Join.Target)
	}
	for i := range c.Common.Peers {
		if c.Common.Peers[i].ID == r.Root.Self.ID {
			c.Common.Peers[i].Key = identityHex(r.Root.Self.Key)
		}
	}
	c.Node.IdentityDir = IdentityPath(c, r)
	return c, r, nil
}

func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func write(path string, r Record) error {
	if r.Validate() != nil {
		return ErrInstallation
	}
	db, err := storage.Open(filepath.Join(path, filename))
	if err != nil {
		return err
	}
	raw, err := json.Marshal(r)
	if err == nil {
		err = db.Write(map[string][]byte{"installation": raw})
	}
	err = errors.Join(err, db.Close())
	if err != nil {
		return err
	}
	return syncDirectory(path)
}

// PrepareInit never replaces another operation/identity or a legacy root. An
// interrupted original init resumes its own durable random cluster and key.
func PrepareInit(c config.Node, admin [32]byte, operation string) (Record, error) {
	if checkManaged(c) != nil || admin == ([32]byte{}) || !lifecycle.ValidID(operation) {
		return Record{}, ErrInstallation
	}
	if c.Common.Admin != "" && c.Common.Admin != hex.EncodeToString(admin[:]) {
		return Record{}, ErrInstallation
	}
	if info, err := os.Lstat(c.Node.StateDir); err == nil && !private(info, true) {
		return Record{}, ErrInstallation
	} else if err != nil && !os.IsNotExist(err) {
		return Record{}, err
	}
	lock, err := storage.LockRoot(c.Node.StateDir)
	if err != nil {
		return Record{}, err
	}
	defer lock.Close()
	if _, err = os.Lstat(filepath.Join(c.Node.StateDir, filename)); err == nil {
		r, err := Read(c)
		if err != nil || r.Admin != admin || r.Root.Intent != lifecycle.Init || r.Root.Operation != operation {
			return Record{}, ErrInstallation
		}
		return r, nil
	} else if !os.IsNotExist(err) {
		return Record{}, err
	}
	if c.Common.Cluster != "" {
		return Record{}, errors.New("new init generates its cluster ID; an existing cluster requires join")
	}
	if err = emptyRoot(c); err != nil {
		return Record{}, err
	}
	var self *identity.Identity
	entries, err := os.ReadDir(c.Node.IdentityDir)
	if os.IsNotExist(err) || err == nil && len(entries) == 0 {
		self, err = identity.Create(c.Node.IdentityDir)
	} else if err == nil {
		self, err = identity.Load(c.Node.IdentityDir)
	}
	if err != nil {
		return Record{}, err
	}
	defer clear(self.Private)
	var cluster [32]byte
	if _, err = rand.Read(cluster[:]); err != nil {
		return Record{}, err
	}
	prepared, err := lifecycle.Prepare(lifecycle.Init, cluster, self.Public, lifecycle.Member{ID: c.Node.ID, Key: self.Public, Voter: true}, operation)
	if err != nil {
		return Record{}, err
	}
	r := Record{Schema: 1, Root: prepared, Admin: admin, Endpoint: c.Node.Listen, Genesis: config.Peer{ID: c.Node.ID, Key: self.Actor(), Endpoint: c.Node.Listen, Voter: true}}
	r.Signature = ed25519.Sign(self.Private, signingBytes(r))
	if err = write(c.Node.StateDir, r); err != nil {
		return Record{}, err
	}
	// Persist newly created root/identity names, not just their leaf files.
	for _, path := range []string{filepath.Dir(c.Node.StateDir), filepath.Dir(c.Node.IdentityDir)} {
		if err = syncDirectory(path); err != nil {
			return Record{}, err
		}
	}
	return r, nil
}

// Install is invoked with the runtime's root lock held and an SDK/FSM-verified
// committed configuration. It only advances the SAME original lifecycle root.
func Install(c config.Node, configuration lifecycle.Configuration, applied uint64) (Record, error) {
	r, err := Read(c)
	if err != nil {
		return r, err
	}
	r.Root, err = r.Root.Install(r.Root.Cluster, configuration, applied)
	if err != nil {
		return r, err
	}
	self, err := identity.Load(IdentityPath(c, r))
	if err != nil {
		return r, err
	}
	defer clear(self.Private)
	r.Signature = ed25519.Sign(self.Private, signingBytes(r))
	err = write(c.Node.StateDir, r)
	return r, err
}

func (r Record) String() string {
	return fmt.Sprintf("cluster=%x node=%s intent=%s operation=%s", r.Root.Cluster, r.Root.Self.ID, r.Root.Intent, r.Root.Operation)
}

func emptyRoot(c config.Node) error {
	identityRoot, err := filepath.Abs(c.Node.IdentityDir)
	if err != nil {
		return err
	}
	stateRoot, err := filepath.Abs(c.Node.StateDir)
	if err != nil {
		return err
	}
	err = filepath.WalkDir(stateRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == stateRoot || path == filepath.Join(stateRoot, "node.lock") {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return ErrInstallation
		}
		rel, toIdentity := filepath.Rel(path, identityRoot)
		ancestor := toIdentity == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
		if entry.IsDir() && ancestor {
			return nil
		}
		if path == filepath.Join(identityRoot, "key.pem") || path == filepath.Join(identityRoot, "cert.pem") {
			return nil
		}
		return errors.New("state root contains existing data; refusing init")
	})
	if err != nil {
		return err
	}

	return nil
}

// SetListen records node.yaml's listen address as this server's address
// after the server moved (its IP or port changed). It changes only this
// server's own signed installation record; the cluster learns the new
// endpoint from `sfcli node set-endpoint`. sfcd must be stopped. It returns
// the address the record had.
func SetListen(c config.Node) (string, error) {
	lock, err := storage.LockRoot(c.Node.StateDir)
	if err != nil {
		return "", fmt.Errorf("stop sfcd first: %w", err)
	}
	defer lock.Close()
	r, err := readRecord(c)
	if err != nil {
		return "", err
	}
	old := r.CurrentListen()
	if c.Node.Listen == old {
		return old, fmt.Errorf("node.yaml listen is already %s; edit node.yaml first", old)
	}
	r.Listen = c.Node.Listen
	if r.Listen == r.Endpoint {
		r.Listen = ""
	}
	self, err := identity.Load(IdentityPath(c, r))
	if err != nil {
		return old, err
	}
	defer clear(self.Private)
	r.Signature = ed25519.Sign(self.Private, signingBytes(r))
	return old, write(c.Node.StateDir, r)
}
