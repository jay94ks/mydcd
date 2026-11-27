// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/web/sfc"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

// volumeView: a data store row as the screens read it, built from sfcd's
// `volumes` row (control.VolumeView): Tenant/App/Name from Scope, Node from
// Owner.Node, Kind fixed (sfcd "node-fixed") or shared. Writer (the one
// writing app service or standalone) comes from the volume-users read and
// is filled only where a screen shows it. UsedBytes is the owner's last
// periodic scan (absent = unknown, never zero) taken at UsageObservedAt
// (Unix ms).
type volumeView struct {
	Key, Tenant, Name string
	Kind              string // shared / fixed
	Node              string `json:",omitempty"`
	Storage           string `json:",omitempty"`
	App               string `json:",omitempty"`
	Revision          uint64
	Consumers         int
	Writer            string  `json:",omitempty"`
	CapacityBytes     uint64  `json:",omitempty"`
	UsedBytes         *uint64 `json:",omitempty"`
	UsageObservedAt   uint64  `json:",omitempty"`
	Retain            bool
	Phase             string           `json:",omitempty"`
	MoveID            string           `json:",omitempty"`
	TargetNode        string           `json:",omitempty"`
	MovePhase         string           `json:",omitempty"`
	Retained          []volumeRetained `json:",omitempty"`
	// Scope and NativeBinding go back to sfcd in change payloads.
	Scope         volumes.Scope `json:"-"`
	NativeBinding [32]byte      `json:"-"`
}

// volumeRetained: a source copy kept after a finished move.
type volumeRetained struct {
	MoveID, Node string
	State        string // retained / deleting / removed
}

func volumeRow(v control.VolumeView) volumeView {
	out := volumeView{Key: v.Key, Tenant: v.Scope.Tenant, Name: v.Scope.ID, App: v.Scope.App, Kind: "shared", Node: v.Owner.Node, Storage: v.Storage,
		Revision: v.Revision, Consumers: v.Consumers, CapacityBytes: v.CapacityBytes, Retain: v.Retain, Phase: v.Phase, MoveID: v.MoveID,
		TargetNode: v.TargetNode, MovePhase: string(v.MovePhase), UsedBytes: v.UsedBytes, UsageObservedAt: v.UsageObservedAt, Scope: v.Scope, NativeBinding: v.NativeBinding}
	if v.Kind == "node-fixed" {
		out.Kind = "fixed"
	}
	for _, r := range v.Retained {
		out.Retained = append(out.Retained, volumeRetained{MoveID: r.Move, Node: r.Node, State: r.State})
	}
	return out
}

// volumePage reads one `volumes` page as screen rows. sfcd keeps a deleted
// volume's row (phase Deleted) as a record; it is no data store any more,
// so the screens do not list it.
func volumePage(ctx context.Context, c sfc.Conn, tenant, after string) (sfc.Page[volumeView], error) {
	p, err := c.Volumes(ctx, tenant, after)
	out := sfc.Page[volumeView]{Items: make([]volumeView, 0, len(p.Items)), Next: p.Next, Revision: p.Revision, Collection: p.Collection, ApprovalRevision: p.ApprovalRevision}
	for _, v := range p.Items {
		if v.Phase == "Deleted" {
			continue
		}
		out.Items = append(out.Items, volumeRow(v))
	}
	return out, err
}

// fillWriters sets each row's Writer from sfcd's volume-users rows: the
// one user that writes (an app service "app/service" or a standalone
// name); none or several leave it empty. A failed read leaves it empty too.
func fillWriters(ctx context.Context, c sfc.Conn, rows []volumeView) {
	for i := range rows {
		v := &rows[i]
		_, users, err := publicReadAll(ctx, c, "volume-users", v.Tenant, control.PublicReadQuery{Name: v.Name, App: v.App})
		if err != nil {
			continue
		}
		us, _, _ := resourceUsers(users, false)
		v.Writer = volumeWriter(us)
	}
}

func volumeWriter(us []resourceUser) string {
	w := ""
	for _, u := range us {
		if u.ReadOnly || u.Kind != sfc.NetworkUserService && u.Kind != sfc.NetworkUserStandalone {
			continue
		}
		if w != "" {
			return ""
		}
		w = u.Standalone
		if u.Kind == sfc.NetworkUserService {
			w = u.App + "/" + u.Service
		}
	}
	return w
}

// sizeHint: a default MaxBytes for a backup or move of v: its capacity,
// else twice the observed size and at least 1 GiB; at most 1 TiB.
func sizeHint(v volumeView) uint64 {
	n := v.CapacityBytes
	if n == 0 {
		n = 1 << 30
		if v.UsedBytes != nil {
			n = max(2**v.UsedBytes, n)
		}
	}
	return min(n, 1<<40)
}
