// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

// volumeRow: the fake's volume state. Volumes hands out control.VolumeView
// (world.volumeView). UsedBytes plays the owner's periodic usage scan:
// the fake shows it as observed at the read time.
type volumeRow struct {
	Key, Tenant, Name string
	Kind              string // shared / fixed
	Node              string
	Storage           string
	App               string // owner app; empty = tenant-registered
	Revision          uint64
	Consumers         int
	CapacityBytes     uint64
	UsedBytes         uint64
	Retain            bool
	Phase             string
	MoveID            string
	TargetNode        string
	MovePhase         string
	ArchiveID         string // the archive that holds the volume (Phase Archived)
	ArchivePhase      string
	Retained          []volumeRetainedRow
	// Scope and NativeBinding identify the volume in change payloads.
	Scope         volumes.Scope
	NativeBinding [32]byte
}

// volumeRetainedRow: one kept source of a finished move.
type volumeRetainedRow struct {
	MoveID, Node string
	State        string // retained / deleting / removed
}

// volumeView: the row as sfcd's `volumes` page shows it (control.Volumes.Page):
// Scope carries Tenant/App/ID, Owner.Node the data's server, Kind is
// "node-fixed" for a fixed volume and empty for a shared one.
func (w *world) volumeView(v volumeRow, nowMillis uint64) control.VolumeView {
	scope := v.Scope
	if scope.ID == "" {
		scope = scopeOf(w, v)
	}
	out := control.VolumeView{Key: v.Key, Scope: scope, Owner: volumes.Owner{Node: v.Node}, Storage: v.Storage, Revision: v.Revision,
		Consumers: v.Consumers, CapacityBytes: v.CapacityBytes, NativeBinding: v.NativeBinding, Retain: v.Retain, Phase: v.Phase,
		MoveID: v.MoveID, TargetNode: v.TargetNode, MovePhase: volumes.Phase(v.MovePhase), ArchiveID: v.ArchiveID, ArchivePhase: v.ArchivePhase}
	used := v.UsedBytes
	out.UsedBytes, out.UsageObservedAt = &used, nowMillis
	if out.Phase == "" {
		out.Phase = "Ready"
	}
	if v.Kind == "fixed" {
		out.Kind = "node-fixed"
	}
	for _, r := range v.Retained {
		out.Retained = append(out.Retained, control.VolumeRetainedSourceView{Move: r.MoveID, Node: r.Node, State: r.State})
		out.RetainedSources++
		switch r.State {
		case "retained":
		case "removed":
			out.RetainedRemoved++
		default:
			out.RetainedPending++
		}
	}
	return out
}
