// SPDX-License-Identifier: Apache-2.0

package app

import (
	"cmp"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"slices"
	"time"
)

// Samples cannot indefinitely outrank expiration/restart. For periodic samples,
// the oldest accepted observation goes first, rather than the same sorted name.
// The report reducer still determines whether the selected action is allowed.
func sortStandalonePolicyWork(work []control.StandaloneWork, now int64) {
	priority := func(w control.StandaloneWork) int {
		m := w.Metadata
		if m.Lifetime == "temp" && (now >= m.ExpiresAt || w.Exited || m.Connections == 0 && m.DisconnectedAt > 0 && now-m.DisconnectedAt >= m.GraceSeconds) || m.Lifetime == "fixed" && m.Desired == "running" && w.Exited && w.Target != nil && (m.Restart == "always" || m.Restart == "on-failure" && w.ExitCode != 0) {
			return 0
		}
		return 1
	}
	slices.SortStableFunc(work, func(a, b control.StandaloneWork) int {
		if p := cmp.Compare(priority(a), priority(b)); p != 0 {
			return p
		}
		return cmp.Compare(a.Metadata.ConnectionAt, b.Metadata.ConnectionAt)
	})
}

func (r *Runtime) standaloneConnection(task string, delta int) {
	r.standaloneMu.Lock()
	defer r.standaloneMu.Unlock()
	if r.standaloneConnections == nil {
		r.standaloneConnections = map[string]int{}
	}
	n := r.standaloneConnections[task] + delta
	if r.standaloneDisconnected == nil {
		r.standaloneDisconnected = map[string]int64{}
	}
	if n <= 0 {
		r.standaloneDisconnected[task] = time.Now().Unix()
		delete(r.standaloneConnections, task)
	} else {
		r.standaloneConnections[task] = n
		delete(r.standaloneDisconnected, task)
	}
}
func (r *Runtime) standaloneConnectionCount(task string) int {
	r.standaloneMu.Lock()
	defer r.standaloneMu.Unlock()
	return r.standaloneConnections[task]
}
func (r *Runtime) advanceStandalonePolicies(ctx context.Context, v cluster.View, apps control.Apps) (bool, error) {
	r.standaloneMu.Lock()
	defer r.standaloneMu.Unlock()
	now := time.Now().Unix()
	work := apps.StandaloneWork(r.Identity.Public)
	sortStandalonePolicyWork(work, now)
	for _, w := range work {
		m := w.Metadata
		action, reason := "", ""
		count := 0
		if w.Target != nil {
			count = r.standaloneConnections[w.Target.Instance]
		}
		if m.Lifetime == "temp" {
			if now >= m.ExpiresAt {
				action, reason = "expire", "ttl"
			} else if w.Exited {
				action, reason = "expire", "exited"
			} else if count == 0 && m.Connections == 0 && m.DisconnectedAt > 0 && now-m.DisconnectedAt >= m.GraceSeconds {
				action, reason = "expire", "disconnected"
			} else if m.Connections != count || w.Target != nil && r.standaloneDisconnected[w.Target.Instance] > m.DisconnectedAt || m.ConnectionAt == 0 || now-m.ConnectionAt >= 10 {
				action = "connections"
			}
		} else if m.Desired == "running" && w.Exited && (m.Restart == "always" || m.Restart == "on-failure" && w.ExitCode != 0) && w.Target != nil && !apps.TaskRestartPending(r.Identity.Public, w.Target.Instance) {
			// The reducer rechecks the original accepted grant and rejects duplicate
			// instance controls. Current root/Volume fences are checked before Start.
			action = "restart"
		} else if m.Lifetime == "fixed" && (m.Connections != count || w.Target != nil && r.standaloneDisconnected[w.Target.Instance] > m.DisconnectedAt || m.ConnectionAt == 0 || now-m.ConnectionAt >= 10) {
			action = "connections"
		}
		if action == "" {
			continue
		}
		q := control.StandalonePolicyReport{Schema: 1, Kind: "standalone-policy", Action: action, Reason: reason, Tenant: w.Tenant, App: w.App, Cluster: r.controlPolicy.Cluster, Reporter: r.commandIdentity().Public, Registration: w.Registration, Authorization: w.Authorization, RootRevision: v.State.Object(control.AppsKey).Revision, Expected: m.Revision, Epoch: v.State.ModuleEpoch(), At: now}
		if action == "connections" {
			q.Connections = count
			if w.Target != nil {
				q.DisconnectedAt = r.standaloneDisconnected[w.Target.Instance]
			}
			if count == 0 && m.Connections > 0 && q.DisconnectedAt == 0 {
				q.DisconnectedAt = now
			}
		}
		if r.Identity.Public != q.Reporter {
			original := r.Identity.Public
			q.ResourceOwner = &original
		}
		q.Signature = ed25519.Sign(r.commandIdentity().Private, control.StandalonePolicyBytes(q))
		if !r.controlPolicy.CheckStandalonePolicy(v.State, q) {
			continue
		}
		raw, _ := json.Marshal(q)
		reply, err := r.appCall(ctx, "standalone-policy-report", raw)
		if err != nil {
			return false, err
		}
		if reply.Committed == nil {
			return false, reconcile.ErrPending
		}
		if reply.Committed.Result.Code == state.Applied {
			return true, nil
		}
	}
	return false, nil
}
