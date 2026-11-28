// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/jay94ks/seafield/internal/clusterapp"
	"github.com/jay94ks/seafield/internal/observability"
	"github.com/jay94ks/seafield/internal/reconcile"
)

// clusterAppLive is one cluster app's state for the host report: its container as
// the owner reads it from the Engine (devel/design/cluster-apps.md 5, step 5),
// or the reason the reconcile pass could not give it a container.
type clusterAppLive struct {
	// Docker is the Engine's container status (created, running, ...);
	// "" when there is no container.
	Docker   string
	Address  string
	Restarts uint64
	// State and Reason, when set, replace the container's state: the image
	// is missing or broken, or the Engine could not be read.
	State, Reason string
	// RunningOn is the server that runs the app instead (State refused).
	RunningOn string
}

// clusterAppProblems keeps the last reconcile outcome of each cluster app that
// did not end in a container, as a fixed state and reason.
type clusterAppProblems struct {
	mu sync.Mutex
	by map[string][2]string
	// refused: apps this sfcd found running on another server (by app,
	// that server). It holds until sfcd restarts: a cluster app never
	// moves on its own (Jay 2026-11-26).
	refused map[string]string
}

// refuse records that app runs on node instead, for good.
func (p *clusterAppProblems) refuse(app, node string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.refused == nil {
		p.refused = map[string]string{}
	}
	p.refused[app] = node
}

// refusedBy is the server app was found running on, if it was.
func (p *clusterAppProblems) refusedBy(app string) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	node, ok := p.refused[app]
	return node, ok
}

func (p *clusterAppProblems) set(app, state, reason string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.by == nil {
		p.by = map[string][2]string{}
	}
	if state == "" {
		delete(p.by, app)
		return
	}
	p.by[app] = [2]string{state, reason}
}

func (p *clusterAppProblems) get(app string) (state, reason string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	v := p.by[app]
	return v[0], v[1]
}

// errClusterAppImageLoad marks a failed load of the cluster app image into the
// Engine.
var errClusterAppImageLoad = errors.New("cluster app image load failed")

// errClusterAppSealKey marks a seal key file node.yaml names that could not
// be read or handed to the container.
var errClusterAppSealKey = errors.New("seal key file")

// errClusterAppPort marks a port node.yaml asks for that could not be opened.
var errClusterAppPort = errors.New("cluster app port could not be opened")

// errClusterAppAddress marks a cluster-wide address this server could not
// hand to its container (network.SetClusterApps).
var errClusterAppAddress = errors.New("cluster app address could not be set")

// clusterAppOutcome maps a reconcile pass's error to a fixed state and reason
// ("" when it ended without a problem).
func clusterAppOutcome(err error) (state, reason string) {
	switch {
	case err == nil:
		return "", ""
	case errors.Is(err, clusterapp.ErrImageNotFound):
		return "image-not-found", "image-not-installed"
	case errors.Is(err, clusterapp.ErrRelease):
		return "image-mismatch", "release-unverified"
	case errors.Is(err, clusterapp.ErrImage):
		return "image-mismatch", "image-digest-mismatch"
	case errors.Is(err, errClusterAppImageLoad):
		return "failed", "image-load-failed"
	case errors.Is(err, errClusterAppSealKey):
		return "failed", "seal-key-unreadable"
	case errors.Is(err, reconcile.ErrLease), errors.Is(err, reconcile.ErrPending):
		// The system network's Bridge is not ready on this server yet; its
		// own failure is in the sfcd log ("managed Bridge sources").
		return "starting", "system-network-pending"
	}
	return "failed", "reconcile-failed"
}

// clusterAppState maps the Engine's container status to a ClusterApp state.
func clusterAppState(docker string) string {
	switch docker {
	case "running":
		return "running"
	case "restarting":
		return "restarting"
	case "removing":
		return "stopping"
	case "exited":
		return "exited"
	case "dead":
		return "failed"
	case "paused":
		// sfcd never pauses a cluster app; someone else did on the server.
		return "failed"
	}
	return "starting" // created, or no container yet
}

func clusterAppControl(c clusterapp.Control) string {
	if c == clusterapp.NodeConfigOnly {
		return "node-config"
	}
	return ""
}

// clusterAppReports are this server's cluster apps for its host report: each one
// node.yaml turns on, the image and version its signed release manifest names,
// its ports, and its state. release reads that manifest (readClusterAppRelease).
// live reads one app (clusterAppLiveState); nil, or nothing known yet, reports
// starting.
func clusterAppReports(ctx context.Context, enabled []string, release func(string) (clusterapp.Release, error), live func(context.Context, string) (clusterAppLive, bool)) []observability.ClusterApp {
	var out []observability.ClusterApp
	for _, name := range enabled {
		image, ok := clusterapp.Lookup(name)
		if !ok {
			continue
		}
		row := observability.ClusterApp{Name: name, Control: clusterAppControl(image.Control), State: "starting", Image: image.Repository}
		for _, p := range image.Ports {
			row.Ports = append(row.Ports, observability.ClusterAppPort{Name: p.Name, Port: p.Port, Protocol: p.Protocol})
		}
		if r, err := release(name); err == nil {
			row.Digest, row.Version = r.Digest, r.Version
		} else {
			row.State, row.Reason = clusterAppOutcome(err)
		}
		if row.State == "starting" && live != nil {
			if v, ok := live(ctx, name); ok {
				row = withClusterAppLive(row, v)
			}
		}
		out = append(out, row)
	}
	return out
}

// readClusterAppRelease reads and verifies an installed cluster app image's
// release manifest against this node's release keys.
func readClusterAppRelease(name string) (clusterapp.Release, error) {
	image, _ := clusterapp.Lookup(name)
	dir, err := clusterapp.InstalledImageDir(image)
	if err != nil {
		return clusterapp.Release{}, err
	}
	trust, err := clusterapp.LoadTrust(clusterapp.KeyDir)
	if err != nil {
		return clusterapp.Release{}, err
	}
	return clusterapp.ReadRelease(dir, image, trust)
}

// withClusterAppLive puts one app's live state on its report row.
func withClusterAppLive(row observability.ClusterApp, v clusterAppLive) observability.ClusterApp {
	row.Address, row.Restarts, row.RunningOn = v.Address, v.Restarts, v.RunningOn
	if v.Docker != "" {
		row.State = clusterAppState(v.Docker)
	}
	if v.State != "" {
		row.State, row.Reason = v.State, v.Reason
	}
	return row
}

// clusterAppLiveState reads one cluster app through its owner (nil while the
// network module is off). A reconcile problem wins over the container: an
// old container may still run while its image is gone.
func (r *Runtime) clusterAppLiveState(ctx context.Context, app string) (clusterAppLive, bool) {
	if r.clusterApps == nil {
		return clusterAppLive{}, false
	}
	var v clusterAppLive
	v.State, v.Reason = r.clusterAppProblems.get(app)
	if node, refused := r.clusterAppProblems.refusedBy(app); refused {
		v.State, v.Reason, v.RunningOn = "refused", "already-running", node
		return v, true
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	st, ok, err := r.clusterApps.Status(ctx, app)
	switch {
	case err != nil:
		if v.State == "" {
			v.State, v.Reason = "unknown", "status-unavailable"
		}
	case ok:
		v.Docker, v.Address, v.Restarts = st.State, st.Address, uint64(max(st.Restarts, 0))
	}
	return v, true
}
