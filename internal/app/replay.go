// SPDX-License-Identifier: Apache-2.0

package app

import (
	"fmt"

	"github.com/jay94ks/seafield/internal/bootstrap"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/identity"
)

// controlHooks gives an engine's options the managed control module, the
// same for a running server (Open) and for an offline replay (Replay).
func controlHooks(o *cluster.Options, catalog control.Policy) {
	o.ModuleID, o.Reduce = catalog.ID(), catalog.Reduce
	o.AdmitModule = catalog.AdmitModule
	o.AdmitMutation = catalog.AdmitAppMutation
	o.AdmitModulePatch = catalog.AdmitAppPatch
	o.AllowMutationUpgrade = true
	o.AllowPatchUpgrade = true
	o.Validate = catalog.ValidateManaged
	o.TrackConfiguration = true
}

// Replay checks a stopped server's copied state root with this build: it
// replays the whole Raft log with the control module that Open would use and
// compares the result with the root's own FSM checkpoint
// (cluster.Replay, devel/design/upgrades.md 3-8). c needs the state root
// (Node.StateDir) and the listen address it was installed with.
func Replay(c config.Node) (state.State, error) {
	c, installation, err := bootstrap.Effective(c)
	if err != nil {
		return state.State{}, err
	}
	clusterID, err := config.ClusterKey(c.Common.Cluster)
	if err != nil {
		return state.State{}, fmt.Errorf("replay: cluster ID: %w", err)
	}
	catalog := control.Policy{Cluster: clusterID, BootstrapKey: installation.Admin, TrustRoot: installation.Root.TrustRoot, Genesis: installation.Genesis}
	if installation.Join == nil {
		for _, p := range c.Common.Peers {
			key, err := identity.ParseKey(p.Key)
			if err != nil {
				return state.State{}, err
			}
			catalog.Issuers = append(catalog.Issuers, key)
		}
	}
	o := cluster.Options{Root: c.Node.StateDir, Admin: c.Common.Admin, Cluster: clusterID}
	controlHooks(&o, catalog)
	return cluster.Replay(o)
}
