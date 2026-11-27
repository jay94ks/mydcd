// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"encoding/json"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/workload"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

// This is a conservative single-volume writer contract, not a database format
// detector or a claim that SQL recovery succeeded. Image config identity pins
// its platform/content; executable, public config and mount layout stay fixed.
// New task/consumer, network and current Secret approval identities may change.
func restoredWriterCompatible(source volumes.ColdSource, backup control.VolumeBackupBinding, target volumes.NativeSpec, next workload.ContainerSpec) bool {
	if !backupSourceMatches(source, backup) || target.Validate() != nil || target.Scope.Cluster != backup.Scope.Cluster || target.Scope.Tenant != backup.Scope.Tenant || target.Node != backup.Source.Spec.Node || target.NodeKey != backup.Source.Spec.NodeKey || target.UID != backup.Source.Spec.UID || target.GID != backup.Source.Spec.GID || target.Mode != backup.Source.Spec.Mode {
		return false
	}
	original, err := workload.DecodeContainer(source.Writer.Task.Spec)
	if err != nil || next.Process == nil || next.Process.Validate() != nil || next.Node != original.Node || next.Image != original.Image || len(original.Volumes) != 1 || len(next.Volumes) != 1 || (next.Inputs == nil) != (original.Inputs == nil) {
		return false
	}
	old, mount := original.Volumes[0], next.Volumes[0]
	if !old.Consumer.Writable || !mount.Consumer.Writable || old.Scope != backup.Scope || mount.Scope != target.Scope || mount.NativeKey != volumes.NativeKey(target) || mount.NativeGeneration != 1 || mount.Target != old.Target {
		return false
	}
	a, _ := json.Marshal(struct {
		Process *workload.Process
		Tmpfs   []workload.Tmpfs
	}{original.Process, original.Tmpfs})
	b, _ := json.Marshal(struct {
		Process *workload.Process
		Tmpfs   []workload.Tmpfs
	}{next.Process, next.Tmpfs})
	return bytes.Equal(a, b)
}

// Called by the same TaskAuthority immediately before SDK Create/Start.
// Historical activations remain original facts, never a second authority:
// current app/Volume/Secret permits are still mandatory at the native edge.
func (r *Runtime) restoredTaskWriter(s state.State, material deployment.TaskMaterial, spec workload.ContainerSpec) error {
	v, err := r.controlPolicy.Volumes(s)
	if err != nil {
		return err
	}
	for _, mount := range spec.Volumes {
		if !mount.Consumer.Writable {
			continue
		}
		for _, restore := range v.Restores() {
			b := restore.Binding
			if b.Target.Scope != mount.Scope {
				continue
			}
			backup, ok := v.Backup(b.Backup.Scope, b.Backup.ID)
			if !ok || backup.Binding.Digest() != b.BackupBinding || restore.Phase != "Restored" || restore.Report == nil || restore.Report.Target == nil || r.activations == nil {
				return volumes.ErrActivation
			}
			matched := false
			for _, ready := range material.Volumes {
				matched = matched || ready.Spec == b.Target && ready.Verify() == nil && ready.Owner == restore.Report.Target.Owner
			}
			if !matched {
				return volumes.ErrActivation
			}
			writers, err := r.activations.ClosedWriters(backup.Binding.Source)
			if err != nil {
				return err
			}
			matched = false
			for _, source := range writers {
				matched = matched || restoredWriterCompatible(source, backup.Binding, b.Target, spec)
			}
			if !matched {
				return volumes.ErrActivation
			}
		}
	}
	return nil
}
