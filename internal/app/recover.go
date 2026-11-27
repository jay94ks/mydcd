// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"slices"
	"sync/atomic"
	"time"

	"github.com/hashicorp/raft"
	"github.com/jay94ks/seafield/internal/bootstrap"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/storage"
)

// RecoveryPreview is what `sfcd recover` shows before it writes a plan.
type RecoveryPreview struct {
	Cluster            [32]byte
	Node               string
	Servers            []raft.Server
	ConfigurationIndex uint64
	LastIndex, Term    uint64
	Voters, Lost       []string
}

// PreviewRecovery reads the stopped node's Raft state and checks the voter
// list. It holds the state root lock, so it fails while sfcd runs.
func PreviewRecovery(c config.Node, voters []string) (RecoveryPreview, error) {
	effective, record, err := bootstrap.Effective(c)
	if err != nil {
		return RecoveryPreview{}, err
	}
	lock, err := storage.LockRoot(effective.Node.StateDir)
	if err != nil {
		return RecoveryPreview{}, fmt.Errorf("stop sfcd first: %w", err)
	}
	defer lock.Close()
	return previewRecovery(effective, record, voters)
}

func previewRecovery(c config.Node, record bootstrap.Record, voters []string) (RecoveryPreview, error) {
	voters = slices.Sorted(slices.Values(voters))
	if len(slices.Compact(slices.Clone(voters))) != len(voters) {
		return RecoveryPreview{}, fmt.Errorf("%w: a server is listed twice", cluster.ErrRecoveryPlan)
	}
	if !slices.Contains(voters, c.Node.ID) {
		return RecoveryPreview{}, fmt.Errorf("%w: --voters must include this server (%s)", cluster.ErrRecoveryPlan, c.Node.ID)
	}
	s, err := cluster.InspectRaft(c.Node.StateDir)
	if err != nil {
		return RecoveryPreview{}, err
	}
	_, lost, err := cluster.RecoveredConfiguration(s.Configuration, voters)
	if err != nil {
		return RecoveryPreview{}, err
	}
	return RecoveryPreview{Cluster: record.Root.Cluster, Node: c.Node.ID, Servers: s.Configuration.Servers, ConfigurationIndex: s.ConfigurationIndex, LastIndex: s.LastIndex, Term: s.Term, Voters: voters, Lost: lost}, nil
}

// PlanRecovery signs and stores the plan with this node's identity key. The
// next `sfcd run` carries it out before Raft starts. confirmIndex must be the
// last log index the operator saw in the preview, so a plan is never made
// against state the operator did not look at.
func PlanRecovery(c config.Node, voters []string, requestID string, confirmIndex uint64, now time.Time) (lifecycle.Recovery, error) {
	effective, record, err := bootstrap.Effective(c)
	if err != nil {
		return lifecycle.Recovery{}, err
	}
	lock, err := storage.LockRoot(effective.Node.StateDir)
	if err != nil {
		return lifecycle.Recovery{}, fmt.Errorf("stop sfcd first: %w", err)
	}
	defer lock.Close()
	p, err := previewRecovery(effective, record, voters)
	if err != nil {
		return lifecycle.Recovery{}, err
	}
	if p.LastIndex != confirmIndex {
		return lifecycle.Recovery{}, fmt.Errorf("%w: the last Raft index is %d, not %d", cluster.ErrRecoveryPlan, p.LastIndex, confirmIndex)
	}
	self, err := identity.Load(effective.Node.IdentityDir)
	if err != nil {
		return lifecycle.Recovery{}, err
	}
	plan := lifecycle.Recovery{Schema: 1, Cluster: p.Cluster, RequestID: requestID, Node: p.Node, Key: self.Public, Voters: p.Voters, PreviousIndex: p.ConfigurationIndex, LastIndex: p.LastIndex, Term: p.Term, CreatedAt: now.Unix()}
	if !plan.WellFormed() {
		return lifecycle.Recovery{}, fmt.Errorf("%w: check --request-id", cluster.ErrRecoveryPlan)
	}
	plan.Signature = ed25519.Sign(self.Private, lifecycle.RecoveryBytes(plan))
	return plan, cluster.WriteRecoveryPlan(effective.Node.StateDir, plan)
}

// recoveryState is the kept result of a recovery the cluster has not
// recorded yet: its members stay refused on SFCP until then.
type recoveryState struct {
	result atomic.Pointer[cluster.RecoveryResult]
}

func (s *recoveryState) load(root string) error {
	r, found, err := cluster.ReadRecoveryResult(root)
	if err != nil || !found {
		return err
	}
	s.result.Store(&r)
	return nil
}

func (s *recoveryState) denied(id string) bool {
	r := s.result.Load()
	return r != nil && slices.Contains(r.Lost, id)
}

// pending returns the plan whose recorded configuration is still to publish.
func (s *recoveryState) pending() (lifecycle.Recovery, bool) {
	if r := s.result.Load(); r != nil {
		return r.Plan, true
	}
	return lifecycle.Recovery{}, false
}

// recorded: every member the local recovery dropped is gone from the
// directory, by this plan or by another survivor's (another request ID).
func (s *recoveryState) recorded(d membership.Directory) bool {
	r := s.result.Load()
	if r == nil {
		return false
	}
	for _, id := range r.Lost {
		if !d.Gone(id) {
			return false
		}
	}
	return true
}

// recoveredMatchesRaft accepts a "recovered" report only for the
// configuration this server's Raft actually runs. A survivor's node root
// alone must not retire the other voters while they are still in Raft.
func (r *Runtime) recoveredMatchesRaft(ctx context.Context, c lifecycle.Configuration) error {
	installed, err := r.Engine().InstalledConfiguration(ctx, false)
	if err != nil {
		return err
	}
	if installed.Index != c.Index || len(installed.Configuration.Servers) != len(c.Members) {
		return sfcp.ErrAdmission
	}
	for _, server := range installed.Configuration.Servers {
		m, found := c.Member(string(server.ID))
		if !found || m.Voter != (server.Suffrage == raft.Voter) {
			return sfcp.ErrAdmission
		}
	}
	return nil
}

// done forgets the result once the cluster recorded it.
func (s *recoveryState) done(root string) error {
	if s.result.Load() == nil {
		return nil
	}
	if err := cluster.RemoveRecoveryResult(root); err != nil {
		return err
	}
	s.result.Store(nil)
	return nil
}
