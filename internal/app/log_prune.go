// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"log"
	"time"

	"golang.org/x/sys/unix"

	"github.com/moby/moby/client"

	"github.com/jay94ks/seafield/internal/logstore"
)

// logPruneTick is how often the log store drops logs of gone containers.
const logPruneTick = 10 * time.Minute

// logPruneLoop applies node.yaml logs (limit, keep) to this server's log
// store: logs of gone containers go after keep, and the longest-gone first
// while the store is over its limit. Logs of containers that still exist
// are never pruned here.
func (r *Runtime) logPruneLoop() {
	defer r.wg.Done()
	ticker := time.NewTicker(logPruneTick)
	defer ticker.Stop()
	for {
		r.pruneLogs()
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (r *Runtime) pruneLogs() {
	if r.logs == nil {
		return
	}
	keep, err := r.logsPolicy.KeepDuration()
	if err != nil {
		return // node.yaml was validated at start
	}
	var fs unix.Statfs_t
	disk := int64(0)
	if unix.Statfs(r.logs.Root(), &fs) == nil && fs.Bsize > 0 {
		disk = int64(fs.Blocks) * fs.Bsize
	}
	limit, err := r.logsPolicy.LimitBytes(disk)
	if err != nil {
		return
	}
	// x-sfc.logs.keep of the log's service or app wins over node.yaml's.
	appKeep := func(tenant, scope, service string) string { return "" }
	ctx := r.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if e := r.Engine(); e != nil {
		if view, err := e.Read(ctx, false); err == nil {
			if f, err := r.controlPolicy.LogKeeps(view.State); err == nil {
				appKeep = f
			}
		}
	}
	keepFor := func(in logstore.Info) time.Duration {
		if in.Tenant == "" || in.App == "" {
			return keep
		}
		if d, ok, err := logstore.ParseKeep(appKeep(in.Tenant, in.App, in.Service)); err == nil && ok {
			return d
		}
		return keep
	}
	removed, err := r.logs.Prune(time.Now(), keepFor, limit)
	if err != nil {
		log.Printf("logs: prune: %v", err)
	}
	if len(removed) > 0 {
		log.Printf("logs: removed the stored logs of %d gone containers", len(removed))
	}
}

// markGoneLogs marks the stored logs whose container the engine no longer
// has. It lists every container, not only this node's own, so a log is
// never marked while its container exists.
func (r *Runtime) markGoneLogs(ctx context.Context) error {
	if r.logs == nil || r.docker == nil {
		return nil
	}
	listed, err := r.docker.API.ContainerList(ctx, client.ContainerListOptions{All: true})
	if err != nil {
		return err
	}
	present := map[string]bool{}
	for _, c := range listed.Items {
		present[c.ID] = true
	}
	stored, err := r.logs.List()
	if err != nil {
		return err
	}
	now := time.Now()
	for _, in := range stored {
		if !present[in.Container] && in.Gone.IsZero() {
			_ = r.logs.MarkGone(in.Container, now)
		}
	}
	return nil
}
