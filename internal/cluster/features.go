// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"errors"
	"fmt"
	"strings"

	"github.com/jay94ks/seafield/internal/buildinfo"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// ErrFeatureUnavailable means the leader did not submit a command because
// some member does not announce a feature the command uses
// (devel/design/upgrades.md 3-2). Nothing was written.
var ErrFeatureUnavailable = errors.New("a cluster member does not have a feature this command uses")

// ErrUnknownFeature means a committed entry uses a feature this build does
// not have. The FSM halts on it instead of diverging from the members that
// applied it; upgrading this server resumes it.
var ErrUnknownFeature = errors.New("Raft entry uses a feature this build does not have")

// haveFeatures refuses an entry that uses a feature this build lacks.
func haveFeatures(index uint64, c state.Command) error {
	return MissingFeatures(fmt.Sprintf("entry %d", index), c.Features, buildinfo.Own, thisServer())
}

// haveStateFeatures refuses a state (a snapshot, a backup) whose entries
// used a feature this build lacks.
func haveStateFeatures(s state.State) error {
	used, ok := s.FeaturesUsed()
	if !ok {
		return fmt.Errorf("%w: unreadable %s", ErrUnknownFeature, state.FeaturesUsedKey)
	}
	return MissingFeatures("this state", used, buildinfo.Own, thisServer())
}

func thisServer() string { return "this server (sfcd " + buildinfo.Version() + ")" }

// MissingFeatures names what of used have lacks, or nil when it has all;
// who is the server that lacks them.
func MissingFeatures(what string, used, have buildinfo.Features, who string) error {
	if have.HasAll(used) {
		return nil
	}
	var missing []string
	for _, f := range used.List() {
		if !have.Has(f) {
			missing = append(missing, f.String())
		}
	}
	return fmt.Errorf("%w: %s uses %s, which %s does not have; upgrade it to a build that has them", ErrUnknownFeature, what, strings.Join(missing, ", "), who)
}

// clusterFeatures is the features every server in the latest Raft
// configuration announces, as this node's transport last saw them. A server
// it cannot resolve counts as having none.
func (e *Engine) clusterFeatures() buildinfo.Features {
	future := e.raft.GetConfiguration()
	if future.Error() != nil {
		return buildinfo.Features{}
	}
	var keys []sfcp.Identity
	for _, server := range future.Configuration().Servers {
		if string(server.ID) == e.id {
			continue
		}
		peer, ok := e.resolve(server.ID, server.Address)
		if !ok {
			return buildinfo.Features{}
		}
		keys = append(keys, peer.Key)
	}
	return e.mesh.ClusterFeatures(keys)
}

// ClusterFeatures is what every server in the latest Raft configuration
// announces, as this node last saw it (empty before the engine runs).
func (e *Engine) ClusterFeatures() buildinfo.Features {
	if e == nil || e.raft == nil || e.mesh == nil {
		return buildinfo.Features{}
	}
	return buildinfo.Own.And(e.clusterFeatures())
}

// submitFeatures checks, before anything is written, that every member has
// the features c uses.
func (e *Engine) submitFeatures(c state.Command) error {
	if c.Features.Empty() {
		return nil
	}
	if !buildinfo.Own.HasAll(c.Features) || !e.clusterFeatures().HasAll(c.Features) {
		return fmt.Errorf("%w: %s", ErrFeatureUnavailable, c.Features)
	}
	return nil
}
