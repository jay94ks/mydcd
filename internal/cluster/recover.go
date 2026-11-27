// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"

	"github.com/hashicorp/raft"
	boltdb "github.com/hashicorp/raft-boltdb/v2"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
)

// Quorum recovery (`sfcd recover`, design B2). The command runs offline on a
// surviving voter and only writes a signed plan. The next engine Open carries
// it out before Raft starts, because replaying the log needs the same reducers
// the running node uses. Open then records the result next to the state and
// the runtime publishes it as the first membership change.

const (
	recoveryPlanFile   = "recovery-plan.json"
	recoveryResultFile = "recovery.json"
)

var ErrRecoveryPlan = errors.New("invalid quorum recovery plan")

// RaftState is what the local Raft stores hold, read without starting Raft.
type RaftState struct {
	Configuration      raft.Configuration
	ConfigurationIndex uint64
	LastIndex, Term    uint64
}

// RecoveryResult is kept after a plan ran: the plan, and the members it
// dropped from the configuration. Until the cluster records the recovery the
// runtime refuses SFCP connections from those members.
type RecoveryResult struct {
	Schema uint8
	Plan   lifecycle.Recovery
	Lost   []string
}

// InspectRaft reads the latest configuration and last log position. The
// caller holds the state root lock, so sfcd is not running.
func InspectRaft(root string) (RaftState, error) {
	logs, err := boltdb.NewBoltStore(filepath.Join(root, "control", "raft.db"))
	if err != nil {
		return RaftState{}, err
	}
	defer logs.Close()
	snapshots, err := raft.NewFileSnapshotStore(filepath.Join(root, "control"), 2, io.Discard)
	if err != nil {
		return RaftState{}, err
	}
	return inspectRaft(logs, snapshots)
}

func inspectRaft(logs raft.LogStore, snapshots raft.SnapshotStore) (RaftState, error) {
	var s RaftState
	list, err := snapshots.List()
	if err != nil {
		return s, err
	}
	if len(list) > 0 {
		s.Configuration, s.ConfigurationIndex = list[0].Configuration, list[0].ConfigurationIndex
		s.LastIndex, s.Term = list[0].Index, list[0].Term
	}
	first, err := logs.FirstIndex()
	if err != nil {
		return s, err
	}
	last, err := logs.LastIndex()
	if err != nil {
		return s, err
	}
	if first < s.LastIndex+1 {
		first = s.LastIndex + 1
	}
	for index := first; index != 0 && index <= last; index++ {
		var entry raft.Log
		if err = logs.GetLog(index, &entry); err != nil {
			return s, err
		}
		if entry.Type == raft.LogConfiguration {
			s.Configuration, s.ConfigurationIndex = raft.DecodeConfiguration(entry.Data), entry.Index
		}
		s.LastIndex, s.Term = entry.Index, entry.Term
	}
	if s.ConfigurationIndex == 0 || len(s.Configuration.Servers) == 0 {
		return s, errors.New("no Raft configuration in local state")
	}
	return s, nil
}

// RecoveredConfiguration is the configuration a plan forces: the plan's
// voters, every non-voter kept, every other voter dropped (lost).
func RecoveredConfiguration(previous raft.Configuration, voters []string) (raft.Configuration, []string, error) {
	var next raft.Configuration
	var lost []string
	found := 0
	for _, server := range previous.Servers {
		listed := slices.Contains(voters, string(server.ID))
		switch {
		case server.Suffrage == raft.Voter && listed:
			found++
			next.Servers = append(next.Servers, server)
		case server.Suffrage == raft.Voter:
			lost = append(lost, string(server.ID))
		case listed:
			return next, nil, fmt.Errorf("%w: %s is not a voter", ErrRecoveryPlan, server.ID)
		default:
			next.Servers = append(next.Servers, server)
		}
	}
	if found != len(voters) {
		return next, nil, fmt.Errorf("%w: every listed server must be a current voter", ErrRecoveryPlan)
	}
	if len(lost) == 0 {
		return next, nil, fmt.Errorf("%w: the list keeps every voter; nothing to recover", ErrRecoveryPlan)
	}
	if len(voters) >= (len(voters)+len(lost))/2+1 {
		return next, nil, fmt.Errorf("%w: the listed voters still hold a majority; remove lost servers with `sfcli node remove --force` instead", ErrRecoveryPlan)
	}
	slices.Sort(lost)
	return next, lost, nil
}

// WriteRecoveryPlan stores a signed plan for the next start. The caller holds
// the state root lock.
func WriteRecoveryPlan(root string, plan lifecycle.Recovery) error {
	if !plan.Valid() {
		return ErrRecoveryPlan
	}
	if _, err := os.Stat(filepath.Join(root, "control", recoveryResultFile)); err == nil {
		return fmt.Errorf("%w: a previous recovery is not recorded by the cluster yet", ErrRecoveryPlan)
	}
	raw, err := json.Marshal(plan)
	if err != nil {
		return err
	}
	return writeFileSynced(filepath.Join(root, "control", recoveryPlanFile), raw)
}

// ReadRecoveryResult returns the kept result, if any.
func ReadRecoveryResult(root string) (RecoveryResult, bool, error) {
	raw, err := os.ReadFile(filepath.Join(root, "control", recoveryResultFile))
	if errors.Is(err, os.ErrNotExist) {
		return RecoveryResult{}, false, nil
	}
	if err != nil {
		return RecoveryResult{}, false, err
	}
	var r RecoveryResult
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || r.Schema != 1 || !r.Plan.Valid() || len(r.Lost) == 0 {
		return RecoveryResult{}, false, ErrRecoveryPlan
	}
	return r, true, nil
}

// RemoveRecoveryResult forgets the result once the cluster recorded it.
func RemoveRecoveryResult(root string) error {
	err := os.Remove(filepath.Join(root, "control", recoveryResultFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func readRecoveryPlan(root string) (lifecycle.Recovery, bool, error) {
	raw, err := os.ReadFile(filepath.Join(root, "control", recoveryPlanFile))
	if errors.Is(err, os.ErrNotExist) {
		return lifecycle.Recovery{}, false, nil
	}
	if err != nil {
		return lifecycle.Recovery{}, false, err
	}
	var plan lifecycle.Recovery
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&plan) != nil || !plan.Valid() {
		return plan, false, ErrRecoveryPlan
	}
	return plan, true, nil
}

// runRecoveryPlan carries out a pending plan before NewRaft. It works like the
// SDK's RecoverCluster, with two differences the durable FSM needs: the FSM
// also sees configuration entries during the replay, and the forced
// configuration gets index LastIndex+1 (not 1) so it is newer than every
// configuration the cluster recorded before.
func (e *Engine) runRecoveryPlan(o Options) error {
	plan, found, err := readRecoveryPlan(o.Root)
	if err != nil || !found {
		return err
	}
	if plan.Cluster != o.Cluster || plan.Node != o.ID {
		return fmt.Errorf("%w: plan is for another cluster or node", ErrRecoveryPlan)
	}
	current, err := inspectRaft(e.log, e.snapshots)
	if err != nil {
		return err
	}
	if e.recoverySnapshotted(o.Root, plan, current) {
		// An earlier start stored the recovered snapshot and stopped before
		// the plan was removed: finish the remaining steps.
		return e.finishRecoveryPlan(o.Root, plan)
	}
	if current.ConfigurationIndex != plan.PreviousIndex || current.LastIndex != plan.LastIndex || current.Term != plan.Term {
		return fmt.Errorf("%w: local Raft state changed after the plan was made", ErrRecoveryPlan)
	}
	next, lost, err := RecoveredConfiguration(current.Configuration, plan.Voters)
	if err != nil {
		return err
	}
	// Replay the newest snapshot and the whole log suffix into the FSM.
	list, err := e.snapshots.List()
	if err != nil {
		return err
	}
	var snapshotIndex uint64
	if len(list) > 0 {
		_, source, err := e.snapshots.Open(list[0].ID)
		if err != nil {
			return err
		}
		if err = e.fsm.Restore(source); err != nil {
			return err
		}
		snapshotIndex = list[0].Index
	}
	first, err := e.log.FirstIndex()
	if err != nil {
		return err
	}
	last, err := e.log.LastIndex()
	if err != nil {
		return err
	}
	if first < snapshotIndex+1 {
		first = snapshotIndex + 1
	}
	for index := first; index != 0 && index <= last; index++ {
		var entry raft.Log
		if err = e.log.GetLog(index, &entry); err != nil {
			return err
		}
		switch entry.Type {
		case raft.LogCommand:
			if r, ok := e.fsm.Apply(&entry).(application); ok && r.Err != nil && e.fsm.failed != nil {
				return r.Err
			}
		case raft.LogConfiguration:
			e.fsm.StoreConfiguration(entry.Index, raft.DecodeConfiguration(entry.Data))
		}
	}
	index := plan.Index()
	f := e.fsm
	f.mu.Lock()
	if f.failed != nil {
		err = f.failed
	} else if !f.ready || f.position > plan.LastIndex {
		err = fmt.Errorf("%w: replay did not reach the last log entry", ErrRecoveryPlan)
	} else {
		f.configuration = raft.EncodeConfiguration(next)
		f.configurationIndex = index
		f.position, f.term = index, plan.Term
		err = f.publish()
	}
	f.mu.Unlock()
	if err != nil {
		return err
	}
	// Keep the result before the snapshot: a start that stops after the
	// snapshot finds both and finishes (recoverySnapshotted).
	raw, err := json.Marshal(RecoveryResult{Schema: 1, Plan: plan, Lost: lost})
	if err != nil {
		return err
	}
	if err = writeFileSynced(filepath.Join(o.Root, "control", recoveryResultFile), raw); err != nil {
		return err
	}
	snapshot, err := f.Snapshot()
	if err != nil {
		return err
	}
	defer snapshot.Release()
	sink, err := e.snapshots.Create(raft.SnapshotVersionMax, index, plan.Term, next, index, e.transport)
	if err != nil {
		return err
	}
	if err = snapshot.Persist(sink); err != nil {
		return err
	}
	return e.finishRecoveryPlan(o.Root, plan)
}

// recoverySnapshotted: the newest snapshot is the plan's recovered one and
// the result is already kept.
func (e *Engine) recoverySnapshotted(root string, plan lifecycle.Recovery, current RaftState) bool {
	result, found, err := ReadRecoveryResult(root)
	if err != nil || !found || result.Plan.RequestID != plan.RequestID || !bytes.Equal(result.Plan.Signature, plan.Signature) {
		return false
	}
	list, err := e.snapshots.List()
	if err != nil || len(list) == 0 || list[0].Index != plan.Index() || list[0].Term != plan.Term || current.ConfigurationIndex != plan.Index() {
		return false
	}
	var voters []string
	for _, server := range current.Configuration.Servers {
		if server.Suffrage == raft.Voter {
			voters = append(voters, string(server.ID))
		}
	}
	slices.Sort(voters)
	return slices.Equal(voters, plan.Voters)
}

// finishRecoveryPlan drops the old log the recovered snapshot replaced (up
// to the plan's last index, never an entry after the snapshot) and the
// plan. It is safe to repeat.
func (e *Engine) finishRecoveryPlan(root string, plan lifecycle.Recovery) error {
	first, err := e.log.FirstIndex()
	if err != nil {
		return err
	}
	last, err := e.log.LastIndex()
	if err != nil {
		return err
	}
	last = min(last, plan.LastIndex)
	if first != 0 && first <= last {
		if err = e.log.DeleteRange(first, last); err != nil {
			return err
		}
	}
	if err = os.Remove(filepath.Join(root, "control", recoveryPlanFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDir(filepath.Join(root, "control"))
}

func writeFileSynced(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".recovery-")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if err = file.Chmod(0o600); err == nil {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(name, path)
	}
	if err == nil {
		err = syncDir(filepath.Dir(path))
	}
	return err
}

func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
