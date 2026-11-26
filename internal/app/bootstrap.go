// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/hashicorp/raft"
	"github.com/jay94ks/mydcd/internal/bootstrap"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/cluster/membership"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/identity"
)

type managedInstallation struct {
	config config.Node
	record bootstrap.Record
}

type Initialized struct {
	Installation   bootstrap.Record
	AwaitingAdmin  bool
	Users, Tenants int
}

// Initialize performs a real N1/Q1 init. The local lifecycle intent precedes
// the first Raft bootstrap; no user/tenant/network/app is created implicitly.
func Initialize(ctx context.Context, c config.Node, admin [32]byte, operation string) (Initialized, error) {
	if _, err := bootstrap.PrepareInit(c, admin, operation); err != nil {
		return Initialized{}, err
	}
	r, err := Open(c)
	if err != nil {
		return Initialized{}, err
	}
	record, installErr := r.InstallConfiguration(ctx)
	if installErr == nil {
		// The first voter makes the cluster's certificate master key; every
		// later voter receives it from a current voter. A repeated init of
		// the same request keeps the key the first attempt stored.
		if n := r.certificateNative(); !n.HasMaster() {
			installErr = n.GenerateMaster()
		}
	}
	var result Initialized
	if installErr == nil {
		view, err := r.Engine().Read(ctx, true)
		installErr = err
		if err == nil {
			catalog, err := (control.Policy{Cluster: record.Root.Cluster, BootstrapKey: record.Admin}).Catalog(view.State)
			installErr = err
			if err == nil {
				result.Installation = record
				result.AwaitingAdmin = catalog.AwaitingAdmin()
				result.Users, result.Tenants = catalog.Counts()
			}
		}
	}
	return result, errors.Join(installErr, r.Close())
}

// InstallConfiguration publishes only the configuration already durably
// installed by the real SDK/FSM. A connection count is never an input.
func (r *Runtime) InstallConfiguration(ctx context.Context) (bootstrap.Record, error) {
	if r.installation == nil {
		return bootstrap.Record{}, errors.New("node has no managed installation intent")
	}
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	var lastWait error = cluster.ErrRecovering
	interrupted := func() error {
		return fmt.Errorf("configuration installation waiting for %v: %w", lastWait, ctx.Err())
	}
	for {
		installed, err := r.Engine().InstalledConfiguration(ctx, r.installation.record.Root.Intent == lifecycle.Init && r.installation.record.Root.Installed.Index == 0)
		if err == nil {
			view, directory, readErr := r.members(ctx, false)
			if readErr != nil {
				return bootstrap.Record{}, readErr
			}
			err = installationIdentityReady(r.installation.record.Root, directory)
			if err == nil {
				configuration := lifecycle.Configuration{Index: installed.Index}
				admitted := true
				for _, server := range installed.Configuration.Servers {
					entry, found := directory.Entry(string(server.ID))
					if !found || string(server.Address) != entry.Peer.Endpoint || server.Suffrage != raft.Voter && server.Suffrage != raft.Nonvoter {
						admitted = false
						break
					}
					if server.Suffrage == raft.Voter && !entry.Peer.Voter && entry.Phase != membership.Promoting {
						admitted = false
						break
					}
					key, _ := identity.ParseKey(entry.CurrentPeer().Key)
					configuration.Members = append(configuration.Members, lifecycle.Member{ID: entry.Peer.ID, Key: key, Voter: server.Suffrage == raft.Voter})
				}
				_, found := configuration.Member(r.installation.record.Root.Self.ID)
				if !admitted {
					return bootstrap.Record{}, errors.New("configuration member lacks committed managed admission")
				}
				if r.installation.record.Join != nil && (!found || view.RaftIndex < r.installation.record.Join.MinimumIndex) {
					err = fmt.Errorf("%w: member_present=%t applied_index=%d minimum_index=%d", cluster.ErrRecovering, found, view.RaftIndex, r.installation.record.Join.MinimumIndex)
				} else {
					sort.Slice(configuration.Members, func(i, j int) bool { return configuration.Members[i].ID < configuration.Members[j].ID })
					// A previous InstallConfiguration call may already have advanced
					// the signed local record without replacing this Runtime's startup
					// record. Project against the actual retained installation evidence.
					currentRecord, readErr := bootstrap.Read(r.installation.config)
					if readErr != nil {
						return bootstrap.Record{}, readErr
					}
					configuration, err = installationConfiguration(currentRecord.Root, directory, configuration)
					if err != nil {
						return bootstrap.Record{}, err
					}
					record, err := bootstrap.Install(r.installation.config, configuration, installed.AppliedIndex)
					return record, err
				}
			}
		}
		if ctx.Err() != nil {
			return bootstrap.Record{}, interrupted()
		}
		if !errors.Is(err, cluster.ErrRecovering) && !errors.Is(err, raft.ErrNotLeader) && !errors.Is(err, raft.ErrLeadershipLost) {
			return bootstrap.Record{}, err
		}
		lastWait = err
		select {
		case <-ctx.Done():
			return bootstrap.Record{}, interrupted()
		case fatal := <-r.Engine().Failure():
			return bootstrap.Record{}, fatal
		case <-ticker.C:
		}
	}
}

// SDK configurations contain IDs/addresses/roles, not identity keys. At an
// unchanged SDK index, retain the original other-member installation evidence
// only when the current committed lineage proves that exact historical key.
// Current transport admission continues to use Directory.CurrentPeer alone.
func installationConfiguration(root lifecycle.Root, directory membership.Directory, configuration lifecycle.Configuration) (lifecycle.Configuration, error) {
	if root.Installed.Index == 0 || configuration.Index != root.Installed.Index {
		return configuration, nil
	}
	if root.Validate() != nil || directory.Cluster != root.Cluster || configuration.Validate() != nil || len(configuration.Members) != len(root.Installed.Members) {
		return lifecycle.Configuration{}, errors.New("configuration installation evidence mismatch")
	}
	configuration.Members = slices.Clone(configuration.Members)
	for i, member := range configuration.Members {
		retained := root.Installed.Members[i]
		if member.ID != retained.ID || member.Voter != retained.Voter {
			return lifecycle.Configuration{}, errors.New("configuration installation evidence mismatch")
		}
		if member.ID == root.Self.ID {
			if member.Key != root.Self.Key {
				return lifecycle.Configuration{}, errors.New("configuration installation self identity mismatch")
			}
			continue
		}
		entry, found := directory.Entry(member.ID)
		original, parseErr := identity.ParseKey(entry.Peer.Key)
		current, valid := lifecycle.ValidIdentityTransitions(root.Cluster, member.ID, original, entry.Keys)
		if !found || parseErr != nil || !valid || current != member.Key || !lifecycle.ResourceIdentity(root.Cluster, member.ID, current, retained.Key, entry.Keys) {
			return lifecycle.Configuration{}, errors.New("configuration installation member identity mismatch")
		}
		configuration.Members[i].Key = retained.Key
	}
	return configuration, nil
}

// A verified local selector may already contain the activated key while the
// reopened local FSM still exposes the earlier Prepared prefix. Install must
// wait for that exact retained lineage, rather than publish the old peer key
// into a new-key Root. This grants no authentication with a historical key.
func installationIdentityReady(root lifecycle.Root, directory membership.Directory) error {
	if len(root.Keys) == 0 {
		return nil // Preserve the original non-rotation installation boundary.
	}
	if root.Validate() != nil || directory.Cluster != root.Cluster {
		return errors.New("configuration installation identity lineage mismatch")
	}
	entry, found := directory.Entry(root.Self.ID)
	if !found {
		return fmt.Errorf("%w: local member identity admission is not applied", cluster.ErrRecovering)
	}
	original, err := identity.ParseKey(entry.Peer.Key)
	current, valid := lifecycle.ValidIdentityTransitions(root.Cluster, root.Self.ID, original, entry.Keys)
	if err != nil || original != root.OriginalKey() || !valid || len(entry.Keys) > len(root.Keys) {
		return errors.New("configuration installation identity lineage mismatch")
	}
	for i, row := range entry.Keys {
		want := root.Keys[i]
		// Root and topology use different revision coordinates; the shared
		// activation command index and complete dual-signed proof are exact.
		if row.Index != want.Index || !bytes.Equal(lifecycle.IdentityProofBytes(row.Proof), lifecycle.IdentityProofBytes(want.Proof)) || !bytes.Equal(row.Proof.OldSignature, want.Proof.OldSignature) || !bytes.Equal(row.Proof.NewSignature, want.Proof.NewSignature) {
			return errors.New("configuration installation identity lineage mismatch")
		}
	}
	peerKey, err := identity.ParseKey(entry.CurrentPeer().Key)
	if err != nil || peerKey != current {
		return errors.New("configuration installation identity lineage mismatch")
	}
	if len(entry.Keys) < len(root.Keys) {
		return fmt.Errorf("%w: local member identity lineage is not applied", cluster.ErrRecovering)
	}
	if current != root.Self.Key {
		return errors.New("configuration installation identity lineage mismatch")
	}
	return nil
}
