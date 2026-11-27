// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/netip"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/ingress"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/workload/volumes"
	"github.com/moby/moby/client"
)

// Resource preflight observes only the owner-local boundary. Source rows come
// from the same exact quorum read-set/replica as the private input plans.
func (r *Runtime) checkMoveResourceReads(ctx context.Context, v cluster.View, resources []control.VolumeMoveResourceRead) (failure error) {
	var current control.VolumeMoveResourceRead
	defer func() {
		if failure != nil && current.Key != "" {
			failure = fmt.Errorf("target resource %s %s on %s: %w", current.Kind, current.Key, current.Node, failure)
		}
	}()
	pinged := false
	projection, err := r.controlPolicy.ProjectResources(v.State)
	if err != nil {
		return err
	}
	for _, row := range resources {
		if row.Owner != r.Identity.Public {
			continue
		}
		current = row
		if r.installation == nil || row.Node != r.installation.record.Root.Self.ID {
			return sfcp.ErrAdmission
		}
		if row.Source.Key != "" {
			o := v.State.Object(row.Source.Key)
			if !o.Present || o.Generation != row.Source.Generation || o.Revision != row.Source.Revision || sha256.Sum256([]byte(o.Value)) != row.Spec {
				return sfcp.ErrAdmission
			}
		}
		if row.Kind == "native-bridge" || row.Kind == "native-tunnel" {
			if err := r.checkMoveNativeNetwork(ctx, v, projection, row); err != nil {
				return err
			}
			continue
		}
		if row.Kind == "native-dns" {
			raw, err := r.observeAppDNS(ctx, row.Key, v)
			if err != nil {
				return err
			}
			o, err := schema.Decode[ModuleObservation](raw)
			if err != nil || o.Schema != 1 || o.Key != row.Key || !o.Ready || o.Generation != row.Source.Generation || o.Revision != row.Source.Revision {
				return fmt.Errorf("target native DNS %s is not ready", row.Key)
			}
			continue
		}
		switch row.Kind {
		case "task", "registry":
			if r.workload == nil {
				return sfcp.ErrAdmission
			}
		case "inputs":
			if r.projections == nil {
				return sfcp.ErrAdmission
			}
		case "volume":
			if r.nativeVolumes == nil || row.Volume == nil || row.Volume.Node != row.Node || row.Volume.NodeKey != r.Identity.Public || row.VolumeGeneration == 0 {
				return sfcp.ErrAdmission
			}
			ready, err := r.nativeVolumes.Ready(ctx, volumes.NativeKey(*row.Volume), r.Identity.Private)
			if err != nil {
				return err
			}
			if ready.Spec != *row.Volume || ready.Generation != row.VolumeGeneration {
				return sfcp.ErrAdmission
			}
		case "dns":
			if r.dnsPath == "" {
				return sfcp.ErrAdmission
			}
		case "bridge":
			if r.network == nil || row.Bridge == nil || row.Bridge.Owner != r.Identity.Public || row.Bridge.Node != row.Node {
				return sfcp.ErrAdmission
			}
			var prefixes []netip.Prefix
			for _, pool := range row.Bridge.Pools {
				prefixes = append(prefixes, pool.Prefix)
			}
			if err := r.network.CheckBridgeSpace(ctx, prefixes); err != nil {
				return err
			}
		case "tunnel":
			if r.tunnel == nil {
				return sfcp.ErrAdmission
			}
			if err := r.tunnel.manager.CheckAccess(ctx); err != nil {
				return err
			}
		case "ingress":
			if r.ingress == nil || row.Ingress == nil || row.Ingress.Node != row.Node {
				return sfcp.ErrAdmission
			}
			var current *ingress.Spec
			if row.Source.Key != "" {
				goal, exists := projection.Goals[row.Source.Key]
				if !exists || goal.Goal.Owner != r.Identity.Public || goal.Ingress == nil {
					return sfcp.ErrAdmission
				}
				current = goal.Ingress
			}
			var listeners []ingress.Listener
			for n, l := range row.Ingress.Listeners {
				listeners = append(listeners, ingress.Listener{ID: fmt.Sprintf("listener-%d", n+1), Address: l.Address, TLS: l.TLS, HTTP3: l.HTTP3})
			}
			if err := r.ingress.CheckListeners(ctx, row.Key, row.Source.Revision, row.Source.Generation, current, listeners); err != nil {
				return err
			}
		default:
			return deployment.ErrInputs
		}
		if !pinged {
			if r.docker == nil {
				return sfcp.ErrAdmission
			}
			if _, err := r.docker.API.Ping(ctx, client.PingOptions{}); err != nil {
				return err
			}
			pinged = true
		}
	}
	return ctx.Err()
}

func (r *Runtime) checkMoveNativeNetwork(ctx context.Context, v cluster.View, projection control.ResourceProjection, row control.VolumeMoveResourceRead) error {
	var record reconcile.Record
	var expected any
	var native string
	var err error
	if row.Kind == "native-bridge" {
		if r.network == nil {
			return sfcp.ErrAdmission
		}
		if source, found := projection.ManagedSources[row.Key]; found && source.Bridge != nil {
			expected = *source.Bridge
		} else if goal, found := projection.Goals[row.Key]; found && goal.Bridge != nil {
			expected = *goal.Bridge
		} else {
			spec, e := network.DecodeBridge(v.State.Object(row.Key).Value)
			if e != nil {
				return e
			}
			expected = spec
		}
		record, err = r.network.View(row.Key)
		if err == nil {
			native, err = r.network.Inspect(ctx, row.Key)
		}
	} else {
		if r.tunnel == nil {
			return sfcp.ErrAdmission
		}
		if source, found := projection.ManagedSources[row.Key]; found && source.Tunnel != nil {
			expected = *source.Tunnel
		} else if goal, found := projection.Goals[row.Key]; found && goal.Tunnel != nil {
			expected = *goal.Tunnel
		} else {
			spec, e := network.DecodeTunnel(v.State.Object(row.Key).Value)
			if e != nil {
				return e
			}
			expected = spec
		}
		record, err = r.tunnel.manager.View(row.Key)
		if err == nil {
			native, err = r.tunnel.manager.Inspect(ctx, row.Key)
		}
		if err == nil {
			err = r.tunnel.Ready(row.Key)
		}
	}
	if err != nil {
		return err
	}
	raw, err := json.Marshal(expected)
	if err != nil {
		return err
	}
	if native == "" || record.State.Pending != nil || record.State.Desired.Revision != row.Source.Revision || !record.State.Applied.Present || record.State.Applied.Generation != row.Source.Generation || record.State.Applied != record.State.Desired.Resource || record.State.Applied.Spec != string(raw) {
		return sfcp.ErrAdmission
	}
	return nil
}
