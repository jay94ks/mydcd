// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jay94ks/seafield/internal/bootstrap"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/eventbus"
	"github.com/jay94ks/seafield/internal/eventlog"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/ingress"
	"github.com/jay94ks/seafield/internal/loginlog"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/nodestorage"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/storage"
	"github.com/jay94ks/seafield/internal/workload"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
	"github.com/jay94ks/seafield/internal/workload/volumes"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"time"
)

func (r *Runtime) openModules(c config.Node, peers map[sfcp.Identity]sfcp.Peer) error {
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
	if openErr == nil {
		node := c.Node.ID
		events.Notify(func(rec eventlog.Record) {
			r.bus.Publish(eventbus.Event{Topic: eventbus.TopicReport, Kind: eventbus.KindDiagnostic, Node: node, Tenant: rec.Event.Target.Tenant, App: rec.Event.Target.App, Changed: true})
		})
	}
	r.mu.Lock()
	r.events = events
	r.eventError = openErr
	r.logins, _ = loginlog.Open(r.reports, c.Node.ID)
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
		r.docker, err = engine.Open(ctx, c.EngineEndpoint(), r.owner)
		cancel()
		if err != nil {
			return fmt.Errorf("network module engine %s: %w", c.EngineEndpoint(), err)
		}
		// Every image the engine pulls is read by sfcd under a ticket
		// (purpose 37); the engine reaches no registry itself.
		r.docker.Images, r.docker.Anonymous = r.engineImages, c.AnonymousImages

		r.network, err = network.OpenManagerWithAdmission(filepath.Join(c.Node.StateDir, "network", "journal.db"), r.docker, r.networkConsumerBudget, r.networkBridgeProtection)

		if err != nil {
			return err
		}
		// Answers for the engine's sfc network driver: the Bridge driver
		// registers each create with it, and the engine asks it at every
		// step (purpose 36).
		r.engineNetwork = &network.EngineHooks{Owner: r.owner, Admit: r.engineNetworkAdmit}
		r.network.UseEngineHooks(r.engineNetwork)
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
		if err = r.openSharedVolumes(c.Node.StateDir); err != nil {
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
		if err == nil && r.logs != nil {
			r.workload.SetLogs(r.logs)
		}

		if err != nil {
			return err
		}
		// sfev.sock directories share the inputs tmpfs mounted above.
		if err = r.workload.AttachSecretSockets(filepath.Join(r.nativeRoot, filepath.FromSlash(bootstrap.InputMemoryDir), "sfev")); err != nil {
			return err
		}
		if r.remoteMounts != nil {
			if err = r.workload.AttachRemoteVolumes(r.remoteMounts); err != nil {
				return err
			}
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
	if err = r.openClusterApps(c); err != nil {
		return err
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
		r.ingress.SetNodeEnroll(r.serveNodeEnroll)
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
		if err = r.Mesh.OnReport(func(ctx context.Context, s *sfcp.Session, kind uint8, b []byte) error {
			r.life.RLock()
			defer r.life.RUnlock()
			if r.closed {
				return errors.New("node is closing")
			}
			switch kind {
			case sfcp.KindEventBatch:
				return r.storeEventBatch(ctx, s.Peer().Key, b)
			case sfcp.KindWorkloadReport:
				return r.storeReport(s.Peer().Key, b)
			case sfcp.KindAppRenewal:
				return r.receiveAppRenewal(ctx, s, b)
			}
			return sfcp.ErrFrame
		}); err != nil {
			return err
		}
	}

	if err = r.openRegistryOwners(); err != nil {
		return err
	}

	r.reportWake = make(chan struct{}, 1)
	r.moduleWake = make(chan struct{}, 1)
	if r.installation != nil && len(r.installation.record.Root.Keys) > 0 {
		r.moduleStart = func() error { return r.startModuleLoops(c, peers) }
		return nil
	}
	return r.startModuleLoops(c, peers)
}
func (r *Runtime) startModuleLoops(c config.Node, peers map[sfcp.Identity]sfcp.Peer) error {
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
	var problem passProblem
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
			r.setModuleErrorLocked(err, time.Now())
			r.mu.Unlock()
			problem.observe(err, time.Now())
			r.wakeReport()
		}
		ok, woken := waitModulePassOrWake(r.ctx, changed, r.moduleWake, reconciled, 2*time.Second)
		if !ok {
			return
		}
		retry = retry || woken
	}
}

// wakeModules asks for a reconciliation pass now, as an engine event (a
// container that died or was OOM-killed) does, instead of at the next tick.
func (r *Runtime) wakeModules() {
	select {
	case r.moduleWake <- struct{}{}:
	default:
	}
}

// passProblem logs a failed reconciliation pass when its cause changes,
// again every stillFailingEvery while the same cause stays, and once when it
// clears. Without it a Task that cannot resolve or pull its image waits with
// nothing in the log; logging only on change left a long stall as one line
// at its start (R18 F7). Registry errors are already sanitized codes.
type passProblem struct {
	text          string
	since, logged time.Time
}

const stillFailingEvery = 10 * time.Minute

func (p *passProblem) observe(err error, now time.Time) {
	switch {
	case err == nil && p.text != "":
		log.Printf("reconciliation recovered after %s", now.Sub(p.since).Round(time.Second))
		*p = passProblem{}
	case err == nil:
	case err.Error() != p.text:
		text := err.Error()
		if len(text) > 2048 {
			text = text[:2048] + "..."
		}
		log.Printf("reconciliation failed, retrying: %s", text)
		*p = passProblem{text: err.Error(), since: now, logged: now}
	case now.Sub(p.logged) >= stillFailingEvery:
		text := p.text
		if len(text) > 2048 {
			text = text[:2048] + "..."
		}
		log.Printf("reconciliation still failing since %s (%s): %s", p.since.UTC().Format(time.RFC3339), now.Sub(p.since).Round(time.Second), text)
		p.logged = now
	}
}

// A completed pass can publish its own observations. Coalesce those notices
// until the next poll instead of treating them (or a tick accumulated during
// a slow pass) as another immediate full reconciliation. The caller then
// reads the latest view and subscription, so changes during this wait remain
// visible. An idle loop still wakes promptly for an external change.
func waitModulePass(ctx context.Context, changed <-chan struct{}, reconciled bool, interval time.Duration) bool {
	ok, _ := waitModulePassOrWake(ctx, changed, nil, reconciled, interval)
	return ok
}

// waitModulePassOrWake is waitModulePass that also returns early on wake and
// says so, so the caller reconciles even when the Raft index did not move.
func waitModulePassOrWake(ctx context.Context, changed, wake <-chan struct{}, reconciled bool, interval time.Duration) (ok, woken bool) {
	if reconciled {
		changed = nil
	}
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false, false
	case <-timer.C:
		return ctx.Err() == nil, false
	case <-changed:
		return ctx.Err() == nil, false
	case <-wake:
		return ctx.Err() == nil, true
	}
}

// The immutable source is staged before any effect. Each manager owns the
// journal/native operation; this composition only orders dependency progress.
func (r *Runtime) reconcileModules(view cluster.View) error {
	stage := newPassWatch()
	defer stage.done()
	stage.enter("certificates")
	certificateFailed := passStep("certificates", r.reconcileCertificates(r.ctx, view))
	stage.enter("ingress-blocks")
	if err := r.applyIngressBlocks(r.ctx, view); err != nil {
		return passStep("ingress-blocks", err)
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
		{"node-disks", func() error { return r.reconcileNodeDisks(r.ctx) }},
		{"node-firewall", func() error { return r.reconcileNodeFirewall(r.ctx, view) }},
		{"node-storage", func() error { return r.reconcileNodeStorage(r.ctx, view) }},
		{"compiler-closures", func() error { return r.reconcileCompilerClosures(r.ctx, view) }},
		{"managed", func() error { return r.reconcileManaged(view) }},
		{"system-network", func() error { return r.reconcileSystemNetwork(r.ctx, view) }},
		{"bridge-closures", func() error { return r.reconcileBridgeClosures(r.ctx, view) }},
		{"network-leaves", func() error { return r.reconcileNetworkLeaves(r.ctx, view) }},
		{"cluster-apps", func() error { return r.reconcileClusterApps(r.ctx, view) }},
		{"cluster-app-ingress", func() error { return r.reconcileClusterAppIngress(r.ctx, view) }},
		{"registries", func() error { return r.reconcileRegistries(r.ctx, view) }},
		{"external-registry-readers", func() error { return r.reconcileExternalRegistryReaders(r.ctx, view) }},
		{"checker-cache", r.collectCheckerCache},
	} {
		stage.enter(step.name)
		failed = errors.Join(failed, passStep(step.name, step.run()))
	}
	ctx, cancel := context.WithTimeout(r.ctx, 15*time.Second)
	defer cancel()
	stage.enter("node-lifecycle")
	lifecycleFailed := passStep("node-lifecycle", r.reconcileNodeLifecycle(ctx, view))
	stage.enter("tenant-retirements")
	return errors.Join(certificateFailed, failed, lifecycleFailed, passStep("tenant-retirements", r.reconcileTenantRetirements(ctx, view)))
}

// passStep names the reconciliation step a failure came from, so the daemon
// log says which owner refused (an unnamed isolation error hid #652).
// errors.Is and errors.As still reach the cause.
func passStep(name string, err error) error {
	if err == nil {
		return nil
	}
	return &stepError{name: name, err: err}
}

type stepError struct {
	name string
	err  error
}

func (e *stepError) Error() string { return e.name + ": " + e.err.Error() }
func (e *stepError) Unwrap() error { return e.err }

// failedSteps lists the step names in err (joined pass errors), in order,
// without duplicates. Only names leave the server; the text stays in the log.
func failedSteps(err error) []string {
	var out []string
	var walk func(error)
	walk = func(err error) {
		switch e := err.(type) {
		case nil:
		case *stepError:
			if !slices.Contains(out, e.name) {
				out = append(out, e.name)
			}
		case interface{ Unwrap() []error }:
			for _, x := range e.Unwrap() {
				walk(x)
			}
		case interface{ Unwrap() error }:
			walk(e.Unwrap())
		}
	}
	walk(err)
	return out
}

// setModuleErrorLocked records the module error and when the current
// failing stretch began. r.mu is held.
func (r *Runtime) setModuleErrorLocked(err error, now time.Time) {
	r.moduleError = err
	switch {
	case err == nil:
		r.moduleErrorSince = time.Time{}
	case r.moduleErrorSince.IsZero():
		r.moduleErrorSince = now
	}
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

// waitedPeers lists the servers err waits for (sfcp.PeerUnreachableError,
// valid names only, in order, without duplicates); only is true when every
// failure in err is such a wait, so one stopped server does not show every
// other server as failing.
func waitedPeers(err error) (peers []string, only bool) {
	only = err != nil
	var walk func(error)
	walk = func(err error) {
		var unreachable *sfcp.PeerUnreachableError
		switch e := err.(type) {
		case nil:
		case interface{ Unwrap() []error }:
			for _, x := range e.Unwrap() {
				walk(x)
			}
		default:
			if errors.As(err, &unreachable) && lifecycle.ValidID(unreachable.Peer) {
				if !slices.Contains(peers, unreachable.Peer) {
					peers = append(peers, unreachable.Peer)
				}
				return
			}
			if u, ok := err.(interface{ Unwrap() error }); ok && u.Unwrap() != nil {
				walk(u.Unwrap())
				return
			}
			only = false
		}
	}
	walk(err)
	return peers, only && len(peers) > 0
}
