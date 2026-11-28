// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http"

	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/observability"
	"github.com/jay94ks/seafield/internal/web/sfc"
)

// diskView: one node-disks row for the screen. The real row may group
// several purposes and storage roots on one filesystem; purpose and
// storageRootID keep the first of each for the existing screens, purposes
// and storageRoots carry all. Sizes are absent while unobserved; times
// are Unix seconds.
type diskView struct {
	Node          string   `json:"node"`
	ID            string   `json:"id,omitempty"`
	Mount         string   `json:"mount"`
	Device        string   `json:"device,omitempty"`
	FSType        string   `json:"fsType,omitempty"`
	State         string   `json:"state"`
	Purpose       string   `json:"purpose"`
	Purposes      []string `json:"purposes"`
	StorageRootID string   `json:"storageRootID,omitempty"`
	StorageRoots  []string `json:"storageRoots"`
	Total         *uint64  `json:"total,omitempty"`
	Used          *uint64  `json:"used,omitempty"`
	Free          *uint64  `json:"free,omitempty"`
	Available     *uint64  `json:"available,omitempty"`
	InodesFree    *uint64  `json:"inodesFree,omitempty"`
	ObservedAt    int64    `json:"observedAt"`
	Stale         bool     `json:"stale"`
	// BlockDevice/BlockClass: the disk the filesystem is on (admin view
	// of one server only).
	BlockDevice string `json:"blockDevice,omitempty"`
	BlockClass  string `json:"blockClass,omitempty"`
}

// disksPage is node-disks' page; devices comes on the first page of a
// system administrator's one-server request.
type disksPage struct {
	listPage
	Devices *devicesView `json:"devices,omitempty"`
}

// devicesView: the server's block devices for the 디스크 tab, grouped by
// class (system / additional / unused) on screen. locked = a system disk:
// the screen shows the manual-work notice instead of buttons. Sizes are
// bytes; observedAt is Unix seconds.
type devicesView struct {
	Node       string          `json:"node"`
	Disks      []blockDiskView `json:"disks"`
	Truncated  bool            `json:"truncated"`
	Recorded   []recordedView  `json:"recorded"`
	Bundles    []bundleView    `json:"bundles"`
	ObservedAt int64           `json:"observedAt"`
	Stale      bool            `json:"stale"`
}

// recordedView: a mount sfcd made; reason empty = mounted now, else why not
// (disk-not-found → 디스크를 찾지 못함, offer 기록 지우기 = action forget).
type recordedView struct {
	UUID   string `json:"uuid"`
	Path   string `json:"path"`
	Disk   string `json:"disk"`
	Part   string `json:"part"`
	Reason string `json:"reason,omitempty"`
}

// bundleView: one disk bundle. state ok / degraded (a mirror runs without
// a member) / missing (not usable) / syncing (syncPercent); device names its
// own row in disks (kind bundle). Members are disks (lvm) or partitions
// (fuse) with state ok / missing / syncing.
type bundleView struct {
	Name        string             `json:"name"`
	Backend     string             `json:"backend"`
	Mode        string             `json:"mode"`
	Size        uint64             `json:"size"`
	Device      string             `json:"device,omitempty"`
	State       string             `json:"state"`
	SyncPercent uint8              `json:"syncPercent"`
	Members     []bundleMemberView `json:"members"`
}

type bundleMemberView struct {
	Disk   string `json:"disk"`
	Part   string `json:"part,omitempty"`
	Serial string `json:"serial,omitempty"`
	WWN    string `json:"wwn,omitempty"`
	Size   uint64 `json:"size,omitempty"`
	State  string `json:"state"`
}

type blockDiskView struct {
	Name       string          `json:"name"`
	Class      string          `json:"class"`
	Kind       string          `json:"kind,omitempty"`
	Bundle     string          `json:"bundle,omitempty"`
	Locked     bool            `json:"locked"`
	Size       uint64          `json:"size"`
	Model      string          `json:"model,omitempty"`
	Serial     string          `json:"serial,omitempty"`
	WWN        string          `json:"wwn,omitempty"`
	Rotational bool            `json:"rotational"`
	ReadOnly   bool            `json:"readOnly"`
	Removable  bool            `json:"removable"`
	Table      string          `json:"table,omitempty"`
	TableID    string          `json:"tableID,omitempty"`
	Purposes   []string        `json:"purposes"`
	Parts      []blockPartView `json:"parts"`
}

type blockSpaceView struct {
	Total     uint64 `json:"total"`
	Used      uint64 `json:"used"`
	Available uint64 `json:"available"`
}

type blockHolderView struct {
	Name   string          `json:"name"`
	Kind   string          `json:"kind"`
	Mapper string          `json:"mapper,omitempty"`
	FSType string          `json:"fsType,omitempty"`
	Mounts []string        `json:"mounts"`
	Swap   bool            `json:"swap"`
	Space  *blockSpaceView `json:"space,omitempty"`
}

type blockPartView struct {
	Name         string            `json:"name"`
	Number       uint32            `json:"number"`
	Size         uint64            `json:"size"`
	FSType       string            `json:"fsType,omitempty"`
	UUID         string            `json:"uuid,omitempty"`
	Label        string            `json:"label,omitempty"`
	Mounts       []string          `json:"mounts"`
	Swap         bool              `json:"swap"`
	Busy         bool              `json:"busy"`
	Holders      []blockHolderView `json:"holders"`
	Space        *blockSpaceView   `json:"space,omitempty"`
	Purposes     []string          `json:"purposes"`
	StorageRoots []string          `json:"storageRoots"`
}

func newSpaceView(s *observability.BlockSpace) *blockSpaceView {
	if s == nil {
		return nil
	}
	return &blockSpaceView{Total: s.Total, Used: s.Used, Available: s.Available}
}

func newDevicesView(d *sfc.NodeDevicesView) *devicesView {
	if d == nil {
		return nil
	}
	v := &devicesView{Node: d.Node, Disks: []blockDiskView{}, Recorded: []recordedView{}, Bundles: []bundleView{}, Truncated: d.Truncated, ObservedAt: int64(d.ObservedAt / 1000), Stale: d.Stale}
	for _, m := range d.Recorded {
		v.Recorded = append(v.Recorded, recordedView{UUID: m.UUID, Path: m.Path, Disk: m.Disk, Part: m.Part, Reason: m.Reason})
	}
	for _, b := range d.Bundles {
		row := bundleView{Name: b.Name, Backend: b.Backend, Mode: b.Mode, Size: b.Size, Device: b.Device, State: b.State, SyncPercent: b.SyncPercent, Members: []bundleMemberView{}}
		for _, m := range b.Members {
			row.Members = append(row.Members, bundleMemberView{Disk: m.Disk, Part: m.Part, Serial: m.Serial, WWN: m.WWN, Size: m.Size, State: m.State})
		}
		v.Bundles = append(v.Bundles, row)
	}
	for _, disk := range d.Disks {
		row := blockDiskView{Name: disk.Name, Class: disk.Class, Kind: disk.Kind, Bundle: disk.Bundle, Locked: disk.Class == "system", Size: disk.Size, Model: disk.Model, Serial: disk.Serial, WWN: disk.WWN,
			Rotational: disk.Rotational, ReadOnly: disk.ReadOnly, Removable: disk.Removable, Table: disk.Table, TableID: disk.TableID,
			Purposes: append([]string{}, disk.Purposes...), Parts: []blockPartView{}}
		for _, p := range disk.Parts {
			part := blockPartView{Name: p.Name, Number: p.Number, Size: p.Size, FSType: p.Filesystem, UUID: p.UUID, Label: p.Label,
				Mounts: append([]string{}, p.Mounts...), Swap: p.Swap, Busy: p.Busy(), Holders: []blockHolderView{}, Space: newSpaceView(p.Space),
				Purposes: append([]string{}, p.Purposes...), StorageRoots: append([]string{}, p.StorageRoots...)}
			for _, h := range p.Holders {
				part.Holders = append(part.Holders, blockHolderView{Name: h.Name, Kind: h.Kind, Mapper: h.Mapper, FSType: h.Filesystem, Mounts: append([]string{}, h.Mounts...), Swap: h.Swap, Space: newSpaceView(h.Space)})
			}
			row.Parts = append(row.Parts, part)
		}
		v.Disks = append(v.Disks, row)
	}
	return v
}

func newDiskView(d sfc.NodeDiskView) diskView {
	v := diskView{Node: d.Node, ID: d.ID, Mount: d.Mount, Device: d.Device, FSType: d.Filesystem, State: d.State,
		Purposes: append([]string{}, d.Purposes...), StorageRoots: append([]string{}, d.StorageRoots...),
		Total: d.Total, Used: d.Used, Free: d.Free, Available: d.Available, InodesFree: d.InodesFree,
		ObservedAt: int64(d.ObservedAt / 1000), Stale: d.Stale, BlockDevice: d.BlockDevice, BlockClass: d.BlockClass}
	if len(d.Purposes) > 0 {
		v.Purpose = d.Purposes[0]
	}
	if len(d.StorageRoots) > 0 {
		v.StorageRootID = d.StorageRoots[0]
	}
	return v
}

// meshView: one mesh-links row. rttMillis/lossPercent/lastHandshakeAt/
// lastChangeAt/observedBy come from the sides' observations, which sfcd
// gives only in the cluster-wide admin view (the worst side wins). Times
// are Unix seconds.
type meshView struct {
	ID              string   `json:"id"`
	NodeA           string   `json:"nodeA"`
	NodeB           string   `json:"nodeB"`
	State           string   `json:"state"`
	RTTMillis       *float64 `json:"rttMillis,omitempty"`
	LossPercent     *float64 `json:"lossPercent,omitempty"`
	LastHandshakeAt int64    `json:"lastHandshakeAt,omitempty"`
	LastChangeAt    int64    `json:"lastChangeAt,omitempty"`
	ObservedBy      string   `json:"observedBy,omitempty"`
	Dialer          string   `json:"dialer,omitempty"`
	ObservedAt      int64    `json:"observedAt"`
	Stale           bool     `json:"stale"`
}

func newMeshView(l sfc.MeshLinkView) meshView {
	v := meshView{ID: l.ID, NodeA: l.NodeA, NodeB: l.NodeB, State: l.State, Dialer: l.Dialer, ObservedAt: int64(l.ObservedAt / 1000), Stale: l.Stale}
	var handshake, change uint64
	for _, e := range l.Ends {
		o := e.Observation
		if o.RTTMillis != nil && (v.RTTMillis == nil || *o.RTTMillis > *v.RTTMillis) {
			x := *o.RTTMillis
			v.RTTMillis = &x
		}
		if o.LossPct != nil && (v.LossPercent == nil || *o.LossPct > *v.LossPercent) {
			x := *o.LossPct
			v.LossPercent = &x
		}
		// The oldest handshake a side reports; a side with none (0) is
		// skipped so the row keeps the reported one (state shows down).
		if o.LastHandshakeAt != 0 && (handshake == 0 || o.LastHandshakeAt < handshake) {
			handshake = o.LastHandshakeAt
		}
		change = max(change, o.LastChangeAt)
		if v.ObservedBy == "" {
			v.ObservedBy = e.ObservedBy
		}
	}
	v.LastHandshakeAt, v.LastChangeAt = int64(handshake/1000), int64(change/1000)
	return v
}

// GET /disks?tenant=&node=&after= and GET /nodes/{node}/disks?tenant=&after=
// → node-disks. No tenant = the cluster-wide admin view.
func (s *Server) handleNodeDisks(w http.ResponseWriter, r *http.Request, ws *webSession) {
	q := r.URL.Query()
	node := r.PathValue("node")
	if node == "" {
		node = q.Get("node")
	}
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (disksPage, error) {
		p, err := c.NodeDisks(ctx, q.Get("tenant"), node, q.Get("after"))
		if err != nil {
			return disksPage{}, err
		}
		rows := make([]diskView, 0, len(p.Disks))
		for _, d := range p.Disks {
			rows = append(rows, newDiskView(d))
		}
		return disksPage{listPage: s.page(rows, p.Next, p.RootRevision), Devices: newDevicesView(p.Devices)}, nil
	})
}

// GET /mesh?tenant=&node=&after= → mesh-links. No tenant = the
// cluster-wide admin view.
func (s *Server) handleMeshLinks(w http.ResponseWriter, r *http.Request, ws *webSession) {
	q := r.URL.Query()
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (listPage, error) {
		p, err := c.MeshLinks(ctx, q.Get("tenant"), q.Get("node"), q.Get("after"))
		if err != nil {
			return listPage{}, err
		}
		rows := make([]meshView, 0, len(p.Links))
		for _, l := range p.Links {
			rows = append(rows, newMeshView(l))
		}
		return s.page(rows, p.Next, p.RootRevision), nil
	})
}

// summaryView: one node-summary row for the screen (Unix seconds). status
// keeps the screens' words: ready, degraded (sfcd unready), unreachable,
// or sfcd's state as is (pending, draining, removed, …). role, cpuPercent
// and memory/disk totals come from the cluster-wide admin view; a tenant
// view carries that tenant's memUsed (when reported) and containers.
type summaryView struct {
	Node   string `json:"node"`
	Status string `json:"status"`
	State  string `json:"state"`
	Ready  bool   `json:"ready"`
	Stale  bool   `json:"stale"`
	// Waiting: sfcd did not hear from the server within the query's wait;
	// the row is what was stored before (shown as "대기 중").
	Waiting bool `json:"waiting,omitempty"`
	// reason (status degraded): MODULE_PASS_FAILED, HOST_READ_FAILED or
	// UNKNOWN; failedSteps names the failing reconciliation steps and
	// failingSince (Unix seconds) when it began (cluster admins only).
	Reason       string   `json:"reason,omitempty"`
	FailedSteps  []string `json:"failedSteps,omitempty"`
	FailingSince int64    `json:"failingSince,omitempty"`
	// admitsWork: false for a server that takes no work; it can still be
	// ready.
	AdmitsWork          bool                  `json:"admitsWork"`
	Role                string                `json:"role,omitempty"`
	CPUPercent          *float64              `json:"cpuPercent,omitempty"`
	MemUsed             *uint64               `json:"memUsed,omitempty"`
	MemTotal            *uint64               `json:"memTotal,omitempty"`
	DiskUsed            *uint64               `json:"diskUsed,omitempty"`
	DiskTotal           *uint64               `json:"diskTotal,omitempty"`
	Containers          uint64                `json:"containers"`
	ObservedAt          int64                 `json:"observedAt"`
	ObserveLimitSeconds uint64                `json:"observeLimitSeconds"`
	CordonedBy          string                `json:"cordonedBy,omitempty"`
	CordonedAt          string                `json:"cordonedAt,omitempty"`
	Scheduling          membership.CordonView `json:"scheduling"`
	ClusterApps         []clusterAppView      `json:"clusterApps,omitempty"`
	// Build: whether image builds can run here; reason is ENGINE_BUILD_OFF,
	// WORKLOAD_OFF or UNKNOWN (no fresh report) when they cannot.
	Build buildView `json:"build"`
}

type buildView struct {
	Enabled bool   `json:"enabled"`
	Reason  string `json:"reason,omitempty"`
}

// clusterAppView is one cluster app on the server for the "기본 제공 앱" card
// (cluster-wide admin view only). actions are the changes its control policy
// allows from the web; node-config allows none (node.yaml only).
type clusterAppView struct {
	Name     string           `json:"name"`
	Image    string           `json:"image"`
	Version  string           `json:"version,omitempty"`
	Digest   string           `json:"digest,omitempty"`
	Ports    []clusterAppPort `json:"ports"`
	State    string           `json:"state"`
	Address  string           `json:"address,omitempty"`
	Reason   string           `json:"reason,omitempty"`
	Restarts uint64           `json:"restarts"`
	Control  string           `json:"control"`
	Actions  []string         `json:"actions"`
	// RunningOn: the server that runs the app instead (state refused,
	// reason already-running): one server in the cluster runs each app.
	RunningOn string `json:"runningOn,omitempty"`
}

// clusterAppPort is one port the cluster app listens on in its container (web
// :8080, acme :8081 for sfc-web).
type clusterAppPort struct {
	Name     string `json:"name"`
	Port     uint16 `json:"port"`
	Protocol string `json:"protocol"`
}

func newSummaryView(n sfc.NodeSummaryView) summaryView {
	v := summaryView{Node: n.Node, Status: n.State, State: n.State, Ready: n.Ready, Stale: n.Stale, Waiting: n.Waiting, ObservedAt: int64(n.ObservedAt / 1000),
		ObserveLimitSeconds: n.ObserveLimitSeconds, CordonedBy: n.CordonedBy, CordonedAt: n.CordonedAt, Scheduling: n.Scheduling, Build: buildView{Enabled: n.Build.Enabled, Reason: n.Build.Reason}}
	if n.State == "unready" {
		v.Status = "degraded"
	}
	v.Reason, v.FailedSteps, v.FailingSince, v.AdmitsWork = n.Reason, n.FailedSteps, int64(n.FailingSince/1000), n.AdmitsWork
	if u := n.Usage; u != nil {
		v.MemUsed = u.MemoryUsed
		if u.Containers != nil {
			v.Containers = *u.Containers
		}
	}
	if a := n.Admin; a != nil {
		v.Role, v.DiskUsed, v.DiskTotal = a.Role, a.DiskUsed, a.DiskTotal
		if h := a.Host; h != nil {
			for _, x := range h.ClusterApps {
				image := x.Image
				if image == "" {
					image = x.Name
				}
				row := clusterAppView{Name: x.Name, Image: image, Version: x.Version, Digest: x.Digest, Ports: []clusterAppPort{}, State: x.State, Address: x.Address, Reason: x.Reason, Restarts: x.Restarts, Control: x.Control, Actions: []string{}, RunningOn: x.RunningOn}
				for _, p := range x.Ports {
					row.Ports = append(row.Ports, clusterAppPort{Name: p.Name, Port: p.Port, Protocol: p.Protocol})
				}
				v.ClusterApps = append(v.ClusterApps, row)
			}
			v.MemUsed, v.MemTotal = h.MemoryUsed, h.MemoryTotal
			if h.CPUUsed != nil && h.CPUCapacity > 0 {
				p := float64(*h.CPUUsed) * 100 / float64(h.CPUCapacity)
				v.CPUPercent = &p
			}
		}
		for _, t := range a.Tenants {
			if t.Containers != nil {
				v.Containers += *t.Containers
			}
		}
	}
	return v
}

// nodeSummaries reads every node-summary page (bounded) as screen rows.
func nodeSummaries(ctx context.Context, c sfc.Conn, tenant string) ([]summaryView, error) {
	out := []summaryView{}
	after := ""
	for i := 0; i < incidentMaxPages; i++ {
		p, err := c.NodeSummary(ctx, tenant, "", after)
		if err != nil {
			return nil, err
		}
		for _, n := range p.Nodes {
			out = append(out, newSummaryView(n))
		}
		if after = p.Next; after == "" {
			break
		}
	}
	return out, nil
}

// GET /nodes/summary?tenant=&node=&after= → node-summary rows. No tenant =
// the cluster-wide admin view.
func (s *Server) handleNodeSummary(w http.ResponseWriter, r *http.Request, ws *webSession) {
	q := r.URL.Query()
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (listPage, error) {
		p, err := c.NodeSummary(ctx, q.Get("tenant"), q.Get("node"), q.Get("after"))
		if err != nil {
			return listPage{}, err
		}
		rows := make([]summaryView, 0, len(p.Nodes))
		for _, n := range p.Nodes {
			rows = append(rows, newSummaryView(n))
		}
		return s.page(rows, p.Next, p.RootRevision), nil
	})
}
