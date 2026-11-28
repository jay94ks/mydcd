// SPDX-License-Identifier: Apache-2.0

package app

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

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
	o.ValidateStage = catalog.ValidateManagedStage
	o.TrackConfiguration = true
}

// Replay checks a stopped server's copied state root with this build: it
// replays the whole Raft log with the control module that Open would use and
// compares the result with the root's own FSM checkpoint
// (cluster.Replay, devel/design/upgrades.md 3-8). c needs the state root
// (Node.StateDir) and the listen address it was installed with.
func Replay(c config.Node) (state.State, error) {
	o, err := replayOptions(c)
	if err != nil {
		return state.State{}, err
	}
	return cluster.Replay(o)
}

// DryRun previews starting this build on c's server without changing it
// (`sfcd upgrade-dry-run`, Jay 2026-11-28): it copies the installation record
// and control state (control/fsm.db, control/raft.db) into scratch and runs
// cluster.DryRun on the copy. The server may keep running: a copy torn by a
// concurrent write is taken again, up to three times.
func DryRun(c config.Node, scratch string) (cluster.DryRunResult, error) {
	var result cluster.DryRunResult
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		root := filepath.Join(scratch, fmt.Sprintf("state-%d", attempt))
		if err = copyControlState(c.Node.StateDir, root); err != nil {
			return result, err
		}
		copied := c
		copied.Node.StateDir = root
		var o cluster.Options
		if o, err = replayOptions(copied); err != nil {
			return result, err
		}
		result, err = cluster.DryRun(o)
		_ = os.RemoveAll(root)
		if err == nil || errors.Is(err, cluster.ErrReplay) {
			return result, err
		}
	}
	return result, err
}

// copyControlState copies what DryRun reads, keeping the private modes the
// stores require.
func copyControlState(from, to string) error {
	for _, dir := range []string{to, filepath.Join(to, "control")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	for _, name := range []string{"installation.db", filepath.Join("control", "fsm.db"), filepath.Join("control", "raft.db")} {
		in, err := os.Open(filepath.Join(from, name))
		if err != nil {
			return err
		}
		out, err := os.OpenFile(filepath.Join(to, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			in.Close()
			return err
		}
		_, err = io.Copy(out, in)
		in.Close()
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func replayOptions(c config.Node) (cluster.Options, error) {
	c, installation, err := bootstrap.Effective(c)
	if err != nil {
		return cluster.Options{}, err
	}
	clusterID, err := config.ClusterKey(c.Common.Cluster)
	if err != nil {
		return cluster.Options{}, fmt.Errorf("replay: cluster ID: %w", err)
	}
	catalog := control.Policy{Cluster: clusterID, BootstrapKey: installation.Admin, TrustRoot: installation.Root.TrustRoot, Genesis: installation.Genesis}
	if installation.Join == nil {
		for _, p := range c.Common.Peers {
			key, err := identity.ParseKey(p.Key)
			if err != nil {
				return cluster.Options{}, err
			}
			catalog.Issuers = append(catalog.Issuers, key)
		}
	}
	o := cluster.Options{Root: c.Node.StateDir, Admin: c.Common.Admin, Cluster: clusterID}
	controlHooks(&o, catalog)
	return o, nil
}
