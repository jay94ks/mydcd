// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/schema"
)

func (r *Runtime) networkDNSRead(ctx context.Context, target control.NetworkDNSTarget) (control.DNSPolicyView, error) {
	out := control.DNSPolicyView{Resolvers: []string{}, State: "unreachable"}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	if ctx.Err() != nil || !r.life.TryRLock() {
		return out, mydcp.ErrAdmission
	}
	defer r.life.RUnlock()
	if r.closed {
		return out, mydcp.ErrAdmission
	}
	var raw []byte
	if target.Owner == r.Identity.Public {
		v, err := r.Engine().Read(ctx, false)
		if err != nil {
			return out, err
		}
		o := v.State.Object(target.Source.Key)
		if !o.Present || o.Generation != target.Source.Generation || o.Revision != target.Source.Revision {
			return out, mydcp.ErrAdmission
		}
		raw, err = r.observeAppDNS(ctx, target.Source.Key, v)
		if err != nil {
			return out, err
		}
	} else {
		peer, ok := r.Mesh.Peer(mydcp.Identity(target.Owner))
		if !ok || !peer.Member || peer.ID != target.Node {
			return out, mydcp.ErrAdmission
		}
		reply, err := cluster.CallManagement(ctx, r.Mesh, r.Identity, r.controlPolicy.Cluster, peer, cluster.ManagementRequest{Method: "observe", Key: target.Source.Key, Latest: false})
		if err != nil {
			return out, err
		}
		raw = reply.Data
	}
	o, err := schema.Decode[ModuleObservation](raw)
	if err != nil || o.Schema != 1 || o.Key != target.Source.Key || o.Generation != target.Source.Generation || o.Revision != target.Source.Revision || o.DNS == nil {
		return out, mydcp.ErrAdmission
	}
	ready := o.Ready && !o.DNS.Stopped && !o.DNS.Failed && o.Error == ""
	out.Ready = &ready
	out.State = "not-ready"
	if ready {
		out.State = "ready"
		out.Resolvers = append([]string{}, o.DNS.Resolvers...)
	}
	return out, nil
}
