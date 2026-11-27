// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/hashicorp/raft"
	boltdb "github.com/hashicorp/raft-boltdb/v2"
	"github.com/jay94ks/seafield/internal/cluster/state"
)

// Full restore (`sfcd restore`, design B4). The command writes the backup's
// MDS1 snapshot and a plan next to an empty state root. The first engine
// Open restores that snapshot into the FSM, applies the plan's command (the
// signed "restored" member report) at RaftIndex+1, installs this server as
// the only voter at the same index and stores the result as the first Raft
// snapshot. Raft then starts from it.

const (
	restorePlanFile     = "restore-plan.json"
	restoreSnapshotFile = "restore-snapshot.mds1"
)

var ErrRestorePlan = errors.New("invalid cluster restore plan")

// RestorePlan is what the next start applies to an empty state root.
type RestorePlan struct {
	Schema          uint8
	Cluster         [32]byte
	RaftIndex, Term uint64
	SnapshotDigest  [32]byte // SHA-256 of the snapshot file
	Command         []byte   // encoded state.Command applied at RaftIndex+1
}

func (p RestorePlan) valid() bool {
	return p.Schema == 1 && p.Cluster != ([32]byte{}) && p.RaftIndex != 0 && p.RaftIndex != ^uint64(0) && p.Term != 0 && p.SnapshotDigest != ([32]byte{}) && len(p.Command) != 0 && len(p.Command) <= 1<<20
}

// WriteRestorePlan stores the snapshot and then the plan. The caller holds
// the state root lock and made the root with bootstrap.PrepareRestore.
func WriteRestorePlan(root string, plan RestorePlan, snapshot []byte) error {
	if !plan.valid() || sha256.Sum256(snapshot) != plan.SnapshotDigest {
		return ErrRestorePlan
	}
	control := filepath.Join(root, "control")
	if err := os.MkdirAll(control, 0o700); err != nil {
		return err
	}
	if err := writeFileSynced(filepath.Join(control, restoreSnapshotFile), snapshot); err != nil {
		return err
	}
	raw, err := json.Marshal(plan)
	if err != nil {
		return err
	}
	return writeFileSynced(filepath.Join(control, restorePlanFile), raw)
}

// RestorePending reports whether a restore plan waits for the next start.
func RestorePending(root string) bool {
	_, err := os.Stat(filepath.Join(root, "control", restorePlanFile))
	return err == nil
}

func readRestorePlan(root string) (RestorePlan, bool, error) {
	raw, err := os.ReadFile(filepath.Join(root, "control", restorePlanFile))
	if errors.Is(err, os.ErrNotExist) {
		return RestorePlan{}, false, nil
	}
	if err != nil {
		return RestorePlan{}, false, err
	}
	var p RestorePlan
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || !p.valid() {
		return p, false, ErrRestorePlan
	}
	return p, true, nil
}

// finishRestorePlan is for a root that has Raft state and a plan: an
// earlier start stored the restored snapshot and stopped before it removed
// the plan. When the newest snapshot is exactly the plan's (RaftIndex+1,
// Term, this server as the only voter) the remaining steps run again;
// anything else is refused.
func (e *Engine) finishRestorePlan(o Options) error {
	plan, found, err := readRestorePlan(o.Root)
	if err != nil || !found {
		return err
	}
	list, err := e.snapshots.List()
	if err != nil {
		return err
	}
	if plan.Cluster != o.Cluster || len(list) == 0 || list[0].Index != plan.RaftIndex+1 || list[0].Term != plan.Term || list[0].ConfigurationIndex != plan.RaftIndex+1 || len(list[0].Configuration.Servers) != 1 {
		return fmt.Errorf("%w: Raft state already exists", ErrRestorePlan)
	}
	server := list[0].Configuration.Servers[0]
	if server.ID != raft.ServerID(o.ID) || server.Suffrage != raft.Voter {
		return fmt.Errorf("%w: Raft state already exists", ErrRestorePlan)
	}
	return e.completeRestorePlan(o.Root, plan)
}

// completeRestorePlan sets the term and removes the plan. Safe to repeat.
func (e *Engine) completeRestorePlan(root string, plan RestorePlan) error {
	term, err := e.log.GetUint64([]byte("CurrentTerm"))
	if err != nil && !errors.Is(err, boltdb.ErrKeyNotFound) {
		return err
	}
	if term < plan.Term {
		if err = e.log.SetUint64([]byte("CurrentTerm"), plan.Term); err != nil {
			return err
		}
	}
	for _, name := range []string{restorePlanFile, restoreSnapshotFile} {
		if err = os.Remove(filepath.Join(root, "control", name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return syncDir(filepath.Join(root, "control"))
}

// runRestorePlan runs before NewRaft on a root without Raft state.
func (e *Engine) runRestorePlan(o Options) (bool, error) {
	plan, found, err := readRestorePlan(o.Root)
	if err != nil || !found {
		return false, err
	}
	if o.Bootstrap || plan.Cluster != o.Cluster || len(o.Servers) != 1 || o.Servers[0].ID != raft.ServerID(o.ID) || o.Servers[0].Suffrage != raft.Voter {
		return false, fmt.Errorf("%w: plan is for another cluster or node", ErrRestorePlan)
	}
	if _, err = state.DecodeCommand(plan.Command); err != nil {
		return false, fmt.Errorf("%w: %v", ErrRestorePlan, err)
	}
	file, err := os.Open(filepath.Join(o.Root, "control", restoreSnapshotFile))
	if err != nil {
		return false, err
	}
	h := sha256.New()
	err = e.fsm.Restore(io.NopCloser(io.TeeReader(file, h)))
	if err == nil {
		_, err = io.Copy(h, file)
	}
	file.Close()
	if err != nil {
		return false, err
	}
	if [32]byte(h.Sum(nil)) != plan.SnapshotDigest {
		return false, fmt.Errorf("%w: snapshot file changed", ErrRestorePlan)
	}
	index := plan.RaftIndex + 1
	configuration := raft.Configuration{Servers: o.Servers}
	f := e.fsm
	f.mu.Lock()
	if f.failed != nil {
		err = f.failed
	} else if f.position != plan.RaftIndex || f.term != plan.Term {
		err = fmt.Errorf("%w: snapshot is not at the plan's position", ErrRestorePlan)
	} else {
		// The command below publishes this configuration with its own index.
		f.configuration = raft.EncodeConfiguration(configuration)
		f.configurationIndex = index
	}
	f.mu.Unlock()
	if err != nil {
		return false, err
	}
	result, ok := f.Apply(&raft.Log{Index: index, Term: plan.Term, Type: raft.LogCommand, Data: plan.Command}).(application)
	if !ok || result.Err != nil {
		return false, fmt.Errorf("%w: restore command: %v", ErrRestorePlan, result.Err)
	}
	if result.Result.Code != state.Applied {
		return false, fmt.Errorf("%w: restore command was refused (%v)", ErrRestorePlan, result.Result.Code)
	}
	snapshot, err := f.Snapshot()
	if err != nil {
		return false, err
	}
	defer snapshot.Release()
	sink, err := e.snapshots.Create(raft.SnapshotVersionMax, index, plan.Term, configuration, index, e.transport)
	if err != nil {
		return false, err
	}
	if err = snapshot.Persist(sink); err != nil {
		return false, err
	}
	// Raft must not start below the restored term.
	return true, e.completeRestorePlan(o.Root, plan)
}
