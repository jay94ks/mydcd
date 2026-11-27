// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jay94ks/seafield/internal/bootstrap"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/clusterbackup"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/storage"
)

// RestoreBackup is a verified cluster backup file, read into memory for
// `sfcd restore` (design B4).
type RestoreBackup struct {
	Manifest   clusterbackup.Manifest
	Members    []membership.Entry // servers in the backup; all of them are lost
	Lost       []string           // their names
	Generation uint64             // the restore generation this restore makes
	master     []byte
	snapshot   []byte
	state      state.State
	directory  membership.Directory
}

// Clear wipes the master key.
func (b *RestoreBackup) Clear() { clear(b.master) }

func (b *RestoreBackup) policy() control.Policy {
	m := b.Manifest
	return control.Policy{Cluster: m.Cluster, BootstrapKey: m.Admin, TrustRoot: m.TrustRoot, Genesis: m.Genesis}
}

// ReadRestoreBackup decrypts and checks a whole backup file like
// `sfcli cluster backup verify`, and keeps what restore needs.
func ReadRestoreBackup(r io.Reader, key clusterbackup.Key) (*RestoreBackup, error) {
	c, body, err := clusterbackup.Open(r, key)
	if err != nil {
		return nil, err
	}
	snapshot, err := io.ReadAll(body)
	if err != nil {
		clear(c.Master)
		return nil, clusterbackup.ErrBackup
	}
	b := &RestoreBackup{Manifest: c.Manifest, master: c.Master, snapshot: snapshot}
	m := c.Manifest
	if clusterbackup.VerifySignature(m, c.Signature) != nil || clusterbackup.MasterCheck(m.Cluster, c.Master) != m.MasterCheck || sha256.Sum256(snapshot) != m.SnapshotDigest || uint64(len(snapshot)) != m.SnapshotSize {
		b.Clear()
		return nil, clusterbackup.ErrBackup
	}
	point, st, err := cluster.ReadSnapshot(m.Cluster, bytes.NewReader(snapshot))
	if err != nil || point.RaftIndex != m.RaftIndex || point.Term != m.Term || point.Index != m.Index || point.StateDigest != m.StateDigest {
		b.Clear()
		return nil, clusterbackup.ErrBackup
	}
	b.state = st
	if b.directory, err = b.policy().Members(st); err != nil {
		b.Clear()
		return nil, fmt.Errorf("backup member directory: %w", err)
	}
	t, err := b.directory.Topology()
	if err != nil {
		b.Clear()
		return nil, fmt.Errorf("backup topology: %w", err)
	}
	b.Generation = t.Generation() + 1
	for _, e := range b.directory.Entries {
		b.Members = append(b.Members, e)
		if !b.directory.Gone(e.Peer.ID) {
			b.Lost = append(b.Lost, e.Peer.ID)
		}
	}
	return b, nil
}

// Restored is what a finished restore reports.
type Restored struct {
	Installation bootstrap.Record
	Generation   uint64
	Lost         []string
}

// Restore rebuilds the backup's cluster on this new server, with sfcd
// stopped and an empty state root. The server becomes the only voter, every
// member of the backup is retired, and the master key is sealed to this
// server's identity. A repeated call with the same request resumes.
func Restore(ctx context.Context, c config.Node, b *RestoreBackup, requestID string, now time.Time) (Restored, error) {
	if _, exists := b.directory.Entry(c.Node.ID); exists {
		return Restored{}, fmt.Errorf("%w: the backup already has a server named %s; give this server a new name", cluster.ErrRestorePlan, c.Node.ID)
	}
	m := b.Manifest
	record, err := bootstrap.PrepareRestore(c, bootstrap.Policy{Cluster: m.Cluster, Admin: m.Admin, TrustRoot: m.TrustRoot, Genesis: m.Genesis}, requestID)
	if err != nil {
		return Restored{}, err
	}
	if record.Root.Installed.Index == 0 {
		if err = planRestore(c, record, b, requestID, now); err != nil {
			return Restored{}, err
		}
	}
	r, err := Open(c)
	if err != nil {
		return Restored{}, err
	}
	installed, err := r.InstallConfiguration(ctx)
	if err == nil {
		if n := r.certificateNative(); !n.HasMaster() {
			err = n.InstallMaster(b.master)
		}
	}
	return Restored{Installation: installed, Generation: b.Generation, Lost: b.Lost}, errors.Join(err, r.Close())
}

// planRestore writes the snapshot and the signed "restored" report the next
// engine Open applies, unless a plan or Raft state is already there.
func planRestore(c config.Node, record bootstrap.Record, b *RestoreBackup, requestID string, now time.Time) error {
	lock, err := storage.LockRoot(c.Node.StateDir)
	if err != nil {
		return fmt.Errorf("stop sfcd first: %w", err)
	}
	defer lock.Close()
	if cluster.RestorePending(c.Node.StateDir) {
		return nil
	}
	self, err := identity.Load(bootstrap.IdentityPath(c, record))
	if err != nil {
		return err
	}
	defer clear(self.Private)
	m := b.Manifest
	restore := lifecycle.ClusterRestore{Schema: 1, Cluster: m.Cluster, RequestID: requestID, Node: c.Node.ID, Key: self.Public, Endpoint: c.Node.Listen, Backup: m.Operation,
		RaftIndex: m.RaftIndex, Term: m.Term, StateIndex: m.Index, Generation: b.Generation, CreatedAt: now.Unix()}
	if !restore.WellFormed() {
		return fmt.Errorf("%w: check --request-id", cluster.ErrRestorePlan)
	}
	restore.Signature = ed25519.Sign(self.Private, lifecycle.ClusterRestoreBytes(restore))
	peer := config.Peer{ID: c.Node.ID, Key: self.Actor(), Endpoint: c.Node.Listen, Voter: true}
	// Check the change here; the engine applies it through the same reducer.
	resources, err := b.policy().Resources(b.state)
	if err != nil {
		return err
	}
	if _, err = b.directory.RestoreCluster(restore, peer, resources.Networks.TunnelAddressesInUse()); err != nil {
		return fmt.Errorf("%w: %v", cluster.ErrRestorePlan, err)
	}
	report := control.MemberReport{Schema: 1, Cluster: m.Cluster, Reporter: self.Public, Action: "restored", Node: c.Node.ID, Expected: b.directory.Revision, Peer: peer, Restore: &restore,
		Epoch: b.state.ModuleEpoch(), RootRevision: b.state.Object(control.MembersKey).Revision}
	digest := sha256.Sum256(control.MemberReportBytes(report))
	report.RequestID = fmt.Sprintf("member/%s/%s/%x", report.Node, report.Action, digest)
	report.Signature = ed25519.Sign(self.Private, control.MemberReportBytes(report))
	cmd, err := report.Command()
	if err != nil {
		return err
	}
	raw, err := state.EncodeCommand(cmd)
	if err != nil {
		return err
	}
	return cluster.WriteRestorePlan(c.Node.StateDir, cluster.RestorePlan{Schema: 1, Cluster: m.Cluster, RaftIndex: m.RaftIndex, Term: m.Term, SnapshotDigest: m.SnapshotDigest, Command: raw}, b.snapshot)
}
