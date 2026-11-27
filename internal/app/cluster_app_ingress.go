// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/sha256"
	"errors"
	"strconv"
	"strings"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/ingress"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/tenancy"
)

// clusterAppIngressPrefix keys a cluster app's routes in the ingress manager.
// They come from the cluster setting (control.ClusterAppRouteRecord), not from
// the app projection, so the app ingress loops leave these keys alone.
const clusterAppIngressPrefix = "cluster-app-ingress/"

func clusterAppIngressKey(key string) bool { return strings.HasPrefix(key, clusterAppIngressPrefix) }

// reconcileClusterAppIngress serves each cluster app route record on the server
// it names (devel/design/cluster-apps.md 3.2). One record revision is one
// ingress generation: a changed or removed record drains the old listeners
// first, then the new ones start. The backend is the app's fixed
// address on the server that runs it (tenancy Networks.ClusterAppAddress).
func (r *Runtime) reconcileClusterAppIngress(ctx context.Context, v cluster.View) error {
	if r.ingress == nil || r.installation == nil {
		return nil
	}
	book, err := r.controlPolicy.IngressManagement(v.State)
	if err != nil {
		return err
	}
	resources, err := r.controlPolicy.Resources(v.State)
	if err != nil {
		return err
	}
	networks := resources.Networks
	users := r.controlPolicy.SystemNetworkUsers(v.State, networks)
	self := r.installation.record.Root.Self.ID
	var failed error
	for _, app := range deployment.ClusterAppRoutable {
		rec, on := book.ClusterAppRoute(app)
		var backend *deployment.ClusterAppBackend
		if node, addr, found := networks.ClusterAppAddress(app, users); found {
			backend = &deployment.ClusterAppBackend{Node: node, Address: addr}
		}
		failed = errors.Join(failed, r.reconcileClusterAppRoute(ctx, app, rec, on && rec.Ingress.Node == self, backend, networks.Revision()))
	}
	return failed
}

func (r *Runtime) reconcileClusterAppRoute(ctx context.Context, app string, rec control.ClusterAppRouteRecord, on bool, backend *deployment.ClusterAppBackend, binding uint64) error {
	key := clusterAppIngressPrefix + app
	old, err := r.ingress.Observe(key)
	exists := err == nil
	if exists && !old.Gone && (!on || old.Generation != rec.Revision) {
		if old.Draining {
			return nil // Gone once its requests end
		}
		spec, _, found := r.ingress.NativeSource(key, old.Generation)
		if !found {
			return ingress.ErrRoute
		}
		spec.Lifecycle = schema.Lifecycle{Drain: true, Nonce: clusterAppDrainNonce(key, old.Generation)}
		return r.ingress.Reconcile(ctx, key, old.Revision+1, old.Generation, &spec)
	}
	if !on || exists && old.Generation > rec.Revision {
		return nil
	}
	if exists && old.Gone && old.Generation == rec.Revision {
		return nil // this revision was served and drained already
	}
	spec, err := deployment.ClusterAppIngressSpec(r.owner, app, rec.Ingress, backend, binding)
	if err != nil {
		return err
	}
	revision := max(rec.Revision, old.Revision)
	if exists && old.Gone {
		revision = max(rec.Revision, old.Revision+1) // a new generation after the drained one
	}
	return r.ingress.Reconcile(ctx, key, revision, rec.Revision, &spec)
}

func clusterAppDrainNonce(key string, generation uint64) (nonce [16]byte) {
	sum := sha256.Sum256([]byte("sfc-cluster-app-ingress-drain\x00" + key + "\x00" + strconv.FormatUint(generation, 10)))
	copy(nonce[:], sum[:])
	return nonce
}

// clusterAppDependency is the network a cluster app backend needs on this server:
// the sfc-system Bridge when the app runs here, else this server's
// sfc-system TUN, which carries the packets to the app's server.
func (d ingressDependencies) clusterAppDependency(ctx context.Context, b ingress.BackendSpec) (string, uint64, bool, error) {
	if b.Network != tenancy.SystemNetwork || d.r.installation == nil {
		return "", 0, false, deployment.ErrInputs
	}
	v, err := d.r.Engine().Read(ctx, false)
	if err != nil {
		return "", 0, false, err
	}
	resources, err := d.r.controlPolicy.Resources(v.State)
	if err != nil {
		return "", 0, false, err
	}
	rows, err := resources.Networks.TUNSources("", tenancy.SystemNetwork)
	if err != nil {
		return "", 0, false, err
	}
	self := d.r.installation.record.Root.Self.ID
	for _, row := range rows {
		if row.Network.Node != self || row.Network.Draining {
			continue
		}
		key, local := row.TunnelKey, false
		if b.Node == self {
			key, local = row.BridgeKey, true
		}
		if o := v.State.Object(key); key != "" && o.Present {
			return key, o.Generation, local, nil
		}
	}
	return "", 0, false, deployment.ErrInputs
}
