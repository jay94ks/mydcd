// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/eventlog"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/ingress"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/nodestorage"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/storage"
	"github.com/jay94ks/mydcd/internal/workload"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

func (r *Runtime) openModules(c config.Node, peers map[mydcp.Identity]mydcp.Peer) error {
	var err error

	r.nodeRoots, err = nodestorage.OpenRoots(filepath.Join(c.Node.StateDir, "storage", "roots.db"), r.controlPolicy.Cluster, c.Node.ID, r.Identity.Private)
	if err != nil {
		return err
	}

	r.reports, err = storage.Open(filepath.Join(c.Node.StateDir, "control", "observations.db"))
	if err != nil {
		return err
	}

	events, openErr := eventlog.Open(r.reports, r.controlPolicy.Cluster, c.Node.ID, r.Identity)
	r.mu.Lock()
	r.events = events
	r.eventError = openErr
	r.mu.Unlock()
	if r.checkerSourceBudget == nil {
		r.checkerSourceBudget = &checker.SourceCacheBudget{}
	}
	r.checkerSources, err = checker.OpenSourcesInCacheBudget(r.reports, r.controlPolicy.Cluster, r.Identity.Private, r.checkerSourceBudget)
	if err != nil {
		return err
	}

	rows, err := r.reports.Scan("node/")
	if err != nil {
		return err
	}
	for key, b := range rows {
		var report workload.Report
		if err = json.Unmarshal(b, &report); err != nil {
			return err
		}
		if _, err = workload.DecodeReport(b); err != nil {
			return err
		}
		if key != "node/"+report.Node.ID {
			return errors.New("stored report owner mismatch")
		}
		if _, known := r.policy.Owners[report.Node.ID]; !known {
			return errors.New("stored report owner is not approved")
		}
	}
	r.deliveryErrors = map[string]string{}
	if c.Modules["workload"].Enabled && !c.Modules["network"].Enabled {
		return errors.New("workload requires network")
	}
	if m := c.Modules["network"]; m.Enabled {
		var local config.NetworkLocal
		if err = m.Decode(&local); err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(r.ctx, 30*time.Second)
		r.docker, err = engine.Open(ctx, local.DockerSocket, r.owner)
		cancel()
		if err != nil {
			return fmt.Errorf("network module Docker %s: %w", local.DockerSocket, err)
		}

		r.network, err = network.OpenManagerWithAdmission(filepath.Join(c.Node.StateDir, "network", "journal.db"), r.docker, r.networkConsumerBudget, r.networkBridgeProtection)

		if err != nil {
			return err
		}
		r.tunnel, err = openTunnelRuntime(r, filepath.Join(c.Node.StateDir, "network", "tunnel.db"))
		if err != nil {
			return err
		}
	}
	if c.Modules["workload"].Enabled {
		r.nativeVolumes, err = volumes.OpenNative(filepath.Join(c.Node.StateDir, "workload", "volumes.db"), r.docker)
		if err != nil {
			return err
		}
		r.fixedVolumes, err = volumes.OpenFixed(filepath.Join(c.Node.StateDir, "workload", "fixed", "journal.db"), r.docker, r.nodeRoots, r.controlPolicy.Cluster, c.Node.ID, r.Identity.Private, r.fixedRootAuthority)
		if err != nil {
			return err
		}
		if err = r.nativeVolumes.AttachFixed(r.fixedVolumes); err != nil {
			return err
		}
		r.activations, err = volumes.OpenActivations(filepath.Join(c.Node.StateDir, "workload", "activations.db"), r.nativeVolumes, r.docker, r.controlPolicy.Cluster, r.Identity.Public, r.appVolumePermit)
		if err != nil {
			return err
		}
		r.backupArtifacts, err = openBackupArtifacts(filepath.Join(c.Node.StateDir, "workload", "backups"), r.controlPolicy.Cluster, r.Identity.Public, runtimeBackupBackend{r}, runtimeMoveBackend{r})
		if err != nil {
			return err
		}
		r.volumeRestores, err = reconcile.OpenJournal(filepath.Join(c.Node.StateDir, "workload", "restores.db"))
		if err != nil {
			return err
		}
		if err = r.validateRestoreJournal(); err != nil {
			return err
		}
		store, e := r.appProjectionStore()
		if e != nil {
			return e
		}
		r.workload, err = workload.OpenManagerWithImageAuthority(filepath.Join(c.Node.StateDir, "workload", "journal.db"), r.docker, r.network, store, r.activations, r.appTaskAuthority, r.appTaskImageAuthority)

		if err != nil {
			return err
		}
	}
	if r.workload != nil {
		r.imageBuildNative, err = imagebuild.OpenNativeJobs(r.reports, r.docker, r.imageBuildAuthority)
		if err != nil {
			return err
		}
		r.checkerCompiler, err = checker.OpenCompilerOwner(r.reports, filepath.Join(c.Node.StateDir, "workload", "lifecycle"), r.controlPolicy.Cluster, r.Identity.Private, r.docker, r.compilerAuthority, r.collectCompilerArtifacts)
		if err != nil {
			return err
		}
	}
	if r.network != nil {
		r.dnsPath = filepath.Join(c.Node.StateDir, "network", "dns.db")
		if _, e := os.Stat(r.dnsPath); e == nil {
			if err = r.openAppDNS(); err != nil {
				return err
			}
		} else if !os.IsNotExist(e) {
			return e
		}
	}
	if m := c.Modules["ingress"]; m.Enabled {
		var local config.IngressLocal
		if err = m.Decode(&local); err != nil {
			return err
		}
		if r.network == nil {
			return errors.New("ingress requires network")
		}
		r.ingress, err = ingress.Open(r.ctx, filepath.Join(c.Node.StateDir, "ingress", "runtime.db"), ingressDependencies{r})
		if err != nil {
			return err
		}
		var addresses []netip.Addr
		for _, peer := range peers {
			host, _, e := net.SplitHostPort(peer.Endpoint)
			if e == nil {
				if address, e := netip.ParseAddr(host); e == nil {
					addresses = append(addresses, address)
				}
			}
		}
		if err = r.ingress.ConfigureGateways(local.Gateways, addresses); err != nil {
			return err
		}
		r.ingress.SetCertificateSource(r.ingressCertificates)
		r.ingress.SetEventSink(r.ingressEvent)
	}
	if !r.historicalOwner {
		if err = r.Mesh.OnReport(func(ctx context.Context, s *mydcp.Session, b []byte) error {
			r.life.RLock()
			defer r.life.RUnlock()
			if r.closed {
				return errors.New("node is closing")
			}
			var header struct{ Kind string }
			if json.Unmarshal(b, &header) == nil && header.Kind == "node-observation" {
				return r.storeNodeObservation(s.Peer().Key, b)
			}
			if header.Kind == "node-events" {
				return r.storeEventBatch(ctx, s.Peer().Key, b)
			}
			return r.storeReport(s.Peer().Key, b)
		}); err != nil {
			return err
		}
	}

	if err = r.openRegistryOwners(); err != nil {
		return err
	}

	r.reportWake = make(chan struct{}, 1)
	if r.installation != nil && len(r.installation.record.Root.Keys) > 0 {
		r.moduleStart = func() error { return r.startModuleLoops(c, peers) }
		return nil
	}
	return r.startModuleLoops(c, peers)
}
func (r *Runtime) startModuleLoops(c config.Node, peers map[mydcp.Identity]mydcp.Peer) error {
	if r.imageBuildNative != nil {
		r.wg.Add(1)
		go func() { defer r.wg.Done(); r.imageBuildLoop() }()
	}
	if r.checkerCompiler != nil {
		r.wg.Add(1)
		go func() { defer r.wg.Done(); r.compilerLoop() }()
	}
	r.wg.Add(1)
	go func() { defer r.wg.Done(); r.moduleLoop() }()
	if r.backupArtifacts != nil {
		r.wg.Add(1)
		go func() { defer r.wg.Done(); r.volumeBackupLoop() }()
	}
	if !r.historicalOwner {
		r.wg.Add(1)
		go func() { defer r.wg.Done(); r.managedObservationLoop() }()
		r.wg.Add(1)
		go func() { defer r.wg.Done(); r.managedEventLoop() }()
	}
	if r.workload != nil && r.docker != nil {
		r.wg.Add(1)
		go func() { defer r.wg.Done(); r.managedDockerEventLoop() }()
	}
	return nil
}

func (r *Runtime) wakeReport() {
	select {
	case r.reportWake <- struct{}{}:
	default:
	}
}

func (r *Runtime) moduleLoop() {
	var last uint64
	first, retry := true, false
	for {
		changed := r.Engine().Changes()
		view, err := r.Engine().Read(r.ctx, false)
		reconciled := false
		if err == nil && (first || retry || view.State.Index() != last || r.tenantRetirementPending(view.State) || r.tunnel != nil || r.ingress != nil || len(r.registryRecords) != 0 || r.network != nil || r.checkerSources != nil && !time.Now().Before(r.checkerCacheNext)) {
			err = r.reconcileModules(view)
			reconciled = true
			last = view.State.Index()
			first = false
			retry = err != nil
			r.mu.Lock()
			previous := r.moduleError
			r.moduleError = err
			r.mu.Unlock()
			logModuleError(previous, err)
			r.wakeReport()
		}
		if !waitModulePass(r.ctx, changed, reconciled, 2*time.Second) {
			return
		}
	}
}

// logModuleError writes a failed reconciliation pass to the daemon log when
// its cause changes, and once when it clears. Without it a Task that cannot
// resolve or pull its image waits with nothing in the log; repeating passes
// with the same cause are not logged again. Registry errors are already
// sanitized codes.
func logModuleError(previous, current error) {
	switch {
	case current == nil && previous != nil:
		log.Print("reconciliation recovered")
	case current != nil && (previous == nil || previous.Error() != current.Error()):
		text := current.Error()
		if len(text) > 2048 {
			text = text[:2048] + "..."
		}
		log.Printf("reconciliation failed, retrying: %s", text)
	}
}

// A completed pass can publish its own observations. Coalesce those notices
// until the next poll instead of treating them (or a tick accumulated during
// a slow pass) as another immediate full reconciliation. The caller then
// reads the latest view and subscription, so changes during this wait remain
// visible. An idle loop still wakes promptly for an external change.
func waitModulePass(ctx context.Context, changed <-chan struct{}, reconciled bool, interval time.Duration) bool {
	if reconciled {
		changed = nil
	}
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return ctx.Err() == nil
	case <-changed:
		return ctx.Err() == nil
	}
}

// The immutable source is staged before any effect. Each manager owns the
// journal/native operation; this composition only orders dependency progress.
func (r *Runtime) reconcileModules(view cluster.View) error {
	stage := newPassWatch()
	defer stage.done()
	stage.enter("certificates")
	certificateFailed := r.reconcileCertificates(r.ctx, view)
	stage.enter("ingress-blocks")
	if err := r.applyIngressBlocks(r.ctx, view); err != nil {
		return err
	}
	r.cancelStaleCheckerPreparation(view)
	var failed error
	for _, step := range []struct {
		name string
		run  func() error
	}{
		{"route-gates", func() error { return r.refreshExistingRouteGates(view) }},
		{"image-build-artifacts", func() error { return r.reconcileImageBuildArtifacts(r.ctx, view) }},
		{"image-build-drafts", func() error { return r.reconcileImageBuildDraftFiles(r.ctx, view) }},
		{"node-storage", func() error { return r.reconcileNodeStorage(r.ctx, view) }},
		{"compiler-closures", func() error { return r.reconcileCompilerClosures(r.ctx, view) }},
		{"managed", func() error { return r.reconcileManaged(view) }},
		{"registries", func() error { return r.reconcileRegistries(r.ctx, view) }},
		{"external-registry-readers", func() error { return r.reconcileExternalRegistryReaders(r.ctx, view) }},
		{"checker-cache", r.collectCheckerCache},
	} {
		stage.enter(step.name)
		failed = errors.Join(failed, step.run())
	}
	ctx, cancel := context.WithTimeout(r.ctx, 15*time.Second)
	defer cancel()
	stage.enter("node-lifecycle")
	lifecycleFailed := r.reconcileNodeLifecycle(ctx, view)
	stage.enter("tenant-retirements")
	return errors.Join(certificateFailed, failed, lifecycleFailed, r.reconcileTenantRetirements(ctx, view))
}

// passWatch logs a reconciliation stage that runs longer than a minute, and
// again every minute while it stays there. A pass stuck in one stage would
// otherwise leave the daemon log silent while app steps wait forever.
type passWatch struct {
	mu    sync.Mutex
	name  string
	since time.Time
	stop  chan struct{}
}

func newPassWatch() *passWatch {
	w := &passWatch{since: time.Now(), stop: make(chan struct{})}
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		dumped := false
		for {
			select {
			case <-w.stop:
				return
			case <-ticker.C:
				w.mu.Lock()
				name, since := w.name, w.since
				w.mu.Unlock()
				if elapsed := time.Since(since); elapsed >= time.Minute {
					log.Printf("reconciliation pass still in stage %s after %s", name, elapsed.Round(time.Second))
					if elapsed >= 3*time.Minute && !dumped {
						// Stacks name code locations only, never values.
						dumped = true
						buf := make([]byte, 1<<20)
						log.Printf("reconciliation pass stuck in stage %s; goroutines:\n%s", name, buf[:runtime.Stack(buf, true)])
					}
				}
			}
		}
	}()
	return w
}

func (w *passWatch) enter(name string) {
	w.mu.Lock()
	w.name, w.since = name, time.Now()
	w.mu.Unlock()
}

func (w *passWatch) done() { close(w.stop) }

func settled(r reconcile.Record) bool {
	return r.State.Pending == nil && r.State.Applied == r.State.Desired.Resource && !r.State.Stopped
}
