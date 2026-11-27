// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/desired"
	"github.com/jay94ks/seafield/internal/eventbus"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/storage"
	"github.com/jay94ks/seafield/internal/workload"
	"maps"
	"math"
	"sync"
	"time"

	"github.com/moby/moby/client"
)

const reportAge = 120_000 // Node.ObservedAt and freshness are Unix milliseconds.

func nodeObjects(v cluster.View) map[string]state.Object {
	objects := map[string]state.Object{}
	for _, key := range desired.Sorted(v.State.Objects(desired.NodePrefix)) {
		o := v.State.Object(key)
		if !o.Present {
			continue
		}
		var n desired.NodeSpec
		if json.Unmarshal([]byte(o.Value), &n) == nil {
			objects[n.Owner] = o
		}
	}
	return objects
}

func nodeFloor(v cluster.View, g desired.Graph, owner string) uint64 {
	return g.Eligibility(v.State)[owner].MinRevision
}

// A receipt follows this exact sync. Authenticated owner, current Desired,
// generation, source, labels and bounds are checked before storing a report.
func (r *Runtime) storeReport(key sfcp.Identity, b []byte) error {
	report, err := workload.DecodeReport(b)
	if err != nil {
		return err
	}
	owner := desired.Owner(r.policy.Cluster, [32]byte(key))
	if report.Node.ID != owner {
		return sfcp.ErrAdmission
	}
	if _, known := r.policy.Owners[owner]; !known {
		return sfcp.ErrAdmission
	}
	r.reportMu.Lock()
	defer r.reportMu.Unlock()
	v, err := r.Engine().Read(r.ctx, false)
	if err != nil {
		return err
	}
	g, err := r.policy.Project(v.State)
	if err != nil {
		return err
	}
	s, known := g.Nodes[owner]
	n := report.Node
	o := nodeObjects(v)[owner]
	now := uint64(time.Now().UnixMilli())
	if !known || n.Generation != o.Generation || n.Revision < nodeFloor(v, g, owner) || n.Revision > v.State.Index() || n.ObservedAt > now || now-n.ObservedAt > reportAge || !maps.Equal(n.Labels, s.Labels) || n.Capacity.CPU > s.CPU || n.Capacity.Memory > s.Memory {
		return workload.ErrPlacement
	}
	old, err := r.reports.Get("node/" + owner)
	if err == nil {
		previous, e := workload.DecodeReport(old)
		if e != nil {
			return e
		}
		if bytes.Equal(old, b) {
			return nil
		}
		if previous.Node.Generation == n.Generation && (n.Revision < previous.Node.Revision || n.ObservedAt <= previous.Node.ObservedAt) {
			return errors.New("report order regressed")
		}
	} else if !errors.Is(err, storage.ErrMissing) {
		return err
	}
	if err := r.reports.Write(map[string][]byte{"node/" + owner: b}); err != nil {
		return err
	}
	r.bus.Publish(eventbus.Event{Topic: eventbus.TopicReport, Kind: eventbus.KindNodeReport, Node: owner, Changed: true})
	return nil
}

func (r *Runtime) collectReport(ctx context.Context) (workload.Report, error) {
	v, err := r.Engine().Read(ctx, false)
	if err != nil {
		return workload.Report{}, err
	}
	g, err := r.policy.Project(v.State)
	if err != nil {
		return workload.Report{}, err
	}
	s, known := g.Nodes[r.owner]
	if !known {
		return workload.Report{}, storage.ErrMissing
	}
	o := nodeObjects(v)[r.owner]
	n := workload.Node{ID: r.owner, Generation: o.Generation, Revision: v.State.Index(), ObservedAt: uint64(time.Now().UnixMilli()), Capacity: workload.Resources{CPU: s.CPU, Memory: s.Memory}, Labels: maps.Clone(s.Labels), Ready: r.network != nil && r.workload != nil}
	for key, spec := range g.Ingress {
		if spec.Owner == r.owner && !spec.Lifecycle.Drain {
			if r.ingress == nil {
				n.Ready = false
				continue
			}
			obs, e := r.ingress.Observe(key)
			if e != nil || !obs.Ready || obs.Revision != v.State.Object(key).Revision || obs.Generation != v.State.Object(key).Generation {
				n.Ready = false
			}
		}
	}
	for _, tun := range g.Tunnels {
		if tun.Owner == r.owner && !tun.Lifecycle.Released() {
			key, _, _ := tunnelFor(g.Tunnels, r.owner)
			if r.tunnel == nil || tun.Lifecycle.Drain || r.tunnel.Ready(key) != nil {
				n.Ready = false
			}
		}
	}
	report := workload.Report{Schema: 1, Node: n}
	if r.docker == nil {
		return report, nil
	}
	info, err := r.docker.API.Info(ctx, client.InfoOptions{})
	if err != nil || info.Info.NCPU <= 0 || info.Info.MemTotal <= 0 {
		report.Node.Ready = false
		return report, nil
	}
	n.Capacity.CPU = min(n.Capacity.CPU, uint64(info.Info.NCPU)*1_000_000_000)
	n.Capacity.Memory = min(n.Capacity.Memory, uint64(info.Info.MemTotal))
	filters := client.Filters{}.Add("label", "org.sfc.owner="+r.owner)
	listed, err := r.docker.API.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: filters})
	if err != nil {
		n.Ready = false
		report.Node = n
		return report, nil
	}
	for _, item := range listed.Items {
		actual, e := r.docker.API.ContainerInspect(ctx, item.ID, client.ContainerInspectOptions{})
		if e != nil || actual.Container.HostConfig == nil {
			n.Ready = false
			continue
		}
		host := actual.Container.HostConfig
		if host.NanoCPUs < 0 || host.Memory < 0 || uint64(host.NanoCPUs) > math.MaxUint64-n.Used.CPU || uint64(host.Memory) > math.MaxUint64-n.Used.Memory {
			return report, workload.ErrPlacement
		}
		n.Used.CPU += uint64(host.NanoCPUs)
		n.Used.Memory += uint64(host.Memory)
		key := item.Labels["org.sfc.key"]
		t, known := g.Tasks[key]
		if !known || t.Node != r.owner || t.Lifecycle.Released() || r.workload == nil {
			n.Ready = false
			continue
		}
		id, _, e := r.workload.Observe(ctx, key)
		if e != nil || id != item.ID {
			n.Ready = false
		}
	}
	if r.network != nil {
		for key, spec := range g.Bridges {
			if spec.Owner == r.owner && !spec.Lifecycle.Drain {
				if _, e := r.network.Inspect(ctx, key); e != nil {
					n.Ready = false
				}
			}
		}
	}
	if r.workload != nil {
		for key, spec := range g.Tasks {
			if spec.Node == r.owner && !spec.Lifecycle.Drain {
				if _, e := r.workload.Inspect(ctx, key); e != nil {
					n.Ready = false
				}
			}
		}
	}
	if n.Used.CPU > n.Capacity.CPU || n.Used.Memory > n.Capacity.Memory {
		n.Ready = false
	}
	report.Node = n
	return report, nil
}

func (r *Runtime) reportLoop(peers map[sfcp.Identity]sfcp.Peer) {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-tick.C:
		case <-r.reportWake:
		}
		ctx, cancel := context.WithTimeout(r.ctx, 30*time.Second)
		report, err := r.collectReport(ctx)
		if err != nil {
			r.mu.Lock()
			r.reportError = err
			r.mu.Unlock()
			cancel()
			continue
		}
		b, err := json.Marshal(report)
		if err == nil {
			err = r.storeReport(sfcp.Identity(r.Identity.Public), b)
		}
		r.mu.Lock()
		r.reportError = err
		r.mu.Unlock()
		if err != nil {
			cancel()
			continue
		}
		// Static approved peers are bounded by configuration. A slow peer cannot
		// serialize reconciliation or stop reports reaching the other controls.
		var wg sync.WaitGroup
		permits := make(chan struct{}, 4)
		for _, key := range desired.Sorted(r.policy.Owners) {
			pub := sfcp.Identity(r.policy.Owners[key])
			if pub == sfcp.Identity(r.Identity.Public) {
				continue
			}
			peer, ok := peers[pub]
			if !ok {
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				select {
				case permits <- struct{}{}:
				case <-ctx.Done():
					return
				}
				defer func() { <-permits }()
				call, stop := context.WithTimeout(ctx, 2*time.Second)
				defer stop()
				session, e := r.Mesh.Dial(call, peer)
				if e == nil {
					e = session.Report(call, sfcp.KindWorkloadReport, b)
				}
				r.mu.Lock()
				if e == nil {
					delete(r.deliveryErrors, peer.ID)
				} else {
					r.deliveryErrors[peer.ID] = e.Error()
				}
				r.mu.Unlock()
			}()
		}
		wg.Wait()
		cancel()
	}
}

func (r *Runtime) reportFor(owner string) (workload.Report, error) {
	b, err := r.reports.Get("node/" + owner)
	if err != nil {
		return workload.Report{}, err
	}
	report, err := workload.DecodeReport(b)
	if err != nil {
		return report, fmt.Errorf("stored report: %w", err)
	}
	return report, nil
}
