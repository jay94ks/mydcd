// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"log"
	"math"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/eventbus"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/observability"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/storage"
	"github.com/jay94ks/seafield/internal/workload"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

type observedContainerCPU struct {
	At  time.Time
	CPU container.CPUStats
}

// Edge measurements stay in observations.db, outside the management FSM.
// They may diagnose a node, never authorize a container or reserve capacity.
func (r *Runtime) storeNodeObservation(caller sfcp.Identity, raw []byte) error {
	report, err := observability.Decode(raw)
	if err != nil || report.Key != [32]byte(caller) || report.Cluster != r.controlPolicy.Cluster {
		return sfcp.ErrAdmission
	}
	v, err := r.Engine().Read(r.ctx, false)
	if err != nil {
		return err
	}
	p, err := r.controlPolicy.Current(v.State)
	if err != nil {
		return err
	}
	d, err := p.Members(v.State)
	if err != nil {
		return err
	}
	entry, ok := d.Entry(report.Node)
	key, keyErr := identity.ParseKey(entry.CurrentPeer().Key)
	now := uint64(time.Now().UnixMilli())
	if !ok || keyErr != nil || key != report.Key || !d.MemberKey(report.Key) || report.Index > v.State.Index() || !observability.Fresh(report.At, now) {
		log.Printf("node observation dropped: node=%s source=%s reason=admission member=%t index=%d local-index=%d at=%d now=%d", report.Node, report.Source(), ok && keyErr == nil && key == report.Key && d.MemberKey(report.Key), report.Index, v.State.Index(), report.At, now)
		return sfcp.ErrAdmission
	}
	r.reportMu.Lock()
	defer r.reportMu.Unlock()
	return r.storeValidatedNodeObservation(report, raw)
}

// Caller holds reportMu; report/caller membership/freshness were checked above,
// or the local actual-pull publisher constructed them from the current view.
func (r *Runtime) storeValidatedNodeObservation(report observability.Report, raw []byte) error {
	id := "node-observation/" + report.Node + "/" + report.Source()
	var prior *observability.Report
	if old, e := r.reports.Get(id); e == nil {
		previous, e := observability.Decode(old)
		if e != nil {
			return e
		}
		prior = &previous
		if bytes.Equal(old, raw) {
			return nil
		}
		newPull := previous.RegistryPull != nil && report.RegistryPull != nil && previous.RegistryPull.Sequence < report.RegistryPull.Sequence
		stale := func(reason string) error {
			log.Printf("node observation dropped: node=%s source=%s reason=%s at=%d stored-at=%d index=%d stored-index=%d", report.Node, report.Source(), reason, report.At, previous.At, report.Index, previous.Index)
			return nil
		}
		if previous.Key == report.Key && !newPull && (previous.At >= report.At || report.RegistryPull == nil && previous.Index > report.Index) {
			return stale("older-than-stored")
		} // no stale overwrite
		if previous.Key == report.Key && previous.RegistryPull != nil && report.RegistryPull != nil &&
			(previous.RegistryPull.Sequence > report.RegistryPull.Sequence || previous.RegistryPull.Sequence == report.RegistryPull.Sequence && *previous.RegistryPull != *report.RegistryPull) {
			return stale("older-registry-pull") // an old republished sample cannot replace a new pull
		}
		if previous.Volume != nil && report.Volume != nil && previous.Volume.Binding == report.Volume.Binding && previous.Volume.ScannedAt > report.Volume.ScannedAt {
			return stale("older-volume-scan") // an older scan cannot replace a newer one of the same volume
		}
		if previous.Task != nil && report.Task != nil && (previous.Task.Generation > report.Task.Generation || previous.Task.Generation == report.Task.Generation && previous.Task.Revision > report.Task.Revision) {
			return stale("older-task-revision")
		}
	} else if !errors.Is(e, storage.ErrMissing) {
		return e
	}
	if err := r.appendObservationEvents(prior, report); err != nil {
		return err
	}
	if err := r.reports.Write(map[string][]byte{id: raw}); err != nil {
		return err
	}
	r.publishNodeObservation(report)
	return nil
}

// publishNodeObservation tells event subscribers which observation changed.
// The tenant/app, when the observation belongs to one, decides who may read it.
func (r *Runtime) publishNodeObservation(report observability.Report) {
	e := eventbus.Event{Topic: eventbus.TopicReport, Kind: eventbus.KindNodeObservation, Node: report.Node, Source: report.Source(), Changed: true}
	switch {
	case report.Task != nil:
		e.Tenant, e.App = report.Task.Tenant, report.Task.App
	case report.Usage != nil:
		e.Tenant = report.Usage.Tenant
	case report.RegistryPull != nil:
		e.Tenant = report.RegistryPull.Tenant
	}
	r.bus.Publish(e)
}

func (r *Runtime) nodeObservations(ctx context.Context, v cluster.View) ([]observability.Report, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	d, err := r.controlPolicy.Members(v.State)
	if err != nil {
		return nil, err
	}
	rows, err := r.reports.Scan("node-observation/")
	if err != nil {
		return nil, err
	}
	out := make([]observability.Report, 0, len(rows))
	for path, raw := range rows {
		report, err := observability.Decode(raw)
		if err != nil || path != "node-observation/"+report.Node+"/"+report.Source() {
			return nil, observability.ErrReport
		}
		entry, ok := d.Entry(report.Node)
		key, e := identity.ParseKey(entry.CurrentPeer().Key)
		if ok && e == nil && key == report.Key {
			out = append(out, report)
		}
	}
	return out, ctx.Err()
}

func (r *Runtime) collectNodeObservations(ctx context.Context, v cluster.View) ([][]byte, error) {
	r.observationMu.Lock()
	defer r.observationMu.Unlock()
	p, err := r.controlPolicy.Current(v.State)
	if err != nil {
		return nil, err
	}
	d, err := p.Members(v.State)
	if err != nil {
		return nil, err
	}
	entry, ok := d.Entry(r.Engine().ObservedNodeID())
	if v.State.Index() == 0 || !ok || !d.MemberKey(r.Identity.Public) {
		return nil, errObservationsNotReady
	}
	base := observability.Report{Kind: "node-observation", Schema: 1, Cluster: p.Cluster, Node: entry.Peer.ID, Key: r.Identity.Public, Index: v.State.Index()}
	out := [][]byte{}
	// An invalid sample is dropped on its own, with a log line; it never
	// keeps the node's other reports from being taken.
	appendReport := func(report observability.Report) error {
		report.At = uint64(time.Now().UnixMilli())
		report.Signature = ed25519.Sign(r.Identity.Private, observability.SigningBytes(report))
		if !report.Valid() {
			if c := report.Consensus; c != nil {
				log.Printf("node observation dropped: node=%s source=consensus reason=invalid role=%q leader=%q term=%d applied=%d commit=%d last=%d snapshot-at=%d at=%d log-first=%d log-last=%d", report.Node, c.Role, c.Leader, c.Term, c.AppliedIndex, c.CommitIndex, c.LastIndex, c.SnapshotAt, report.At, c.LogFirstIndex, c.LogLastIndex)
				return nil
			}
			log.Printf("node observation dropped: node=%s source=%s reason=invalid", report.Node, report.Source())
			return nil
		}
		raw, err := json.Marshal(report)
		if err == nil {
			out = append(out, raw)
		}
		return err
	}
	host, counter, hostErr := observability.ReadHost(r.observationCPU)
	host.RuntimeEnabled = r.docker != nil
	r.observationCPU = counter
	r.mu.RLock()
	host.ModuleReady = r.moduleError == nil
	r.mu.RUnlock()
	if r.tunnel != nil {
		host.TunnelWaits = r.tunnel.Waits()
	}
	host.Build = r.buildCapability()
	if r.installation != nil {
		host.ClusterApps = clusterAppReports(ctx, r.installation.config.ClusterApps.Enabled(), readClusterAppRelease, r.clusterAppLiveState)
	}
	if hostErr != nil && host.CPUCapacity == 0 {
		host.ModuleReady = false
	}
	h := base
	h.Host = &host
	if err := appendReport(h); err != nil {
		return nil, err
	}
	// Root and Docker data-root are the only nonregistered filesystem paths.
	paths := map[string]string{"system": "/"}
	if r.docker != nil {
		info, infoErr := r.docker.API.Info(ctx, client.InfoOptions{})
		if infoErr == nil && info.Info.DockerRootDir != "" {
			paths["container-runtime"] = info.Info.DockerRootDir
		}
	}
	for source, path := range paths {
		disk, e := observability.InspectDisk(ctx, base.Node, path)
		if e != nil {
			continue
		} // old successful sample stays stale; never publish zeros
		disk.Source = source
		sample := base
		sample.Disk = &disk
		if err := appendReport(sample); err != nil {
			return nil, err
		}
	}
	// The block device inventory is one report; a busy or failed read
	// keeps the last stored inventory, which goes stale on its own.
	if devices, e := observability.InspectDevices(ctx); e != nil {
		log.Printf("node observation dropped: node=%s source=devices reason=unavailable error=%v", base.Node, e)
	} else {
		devices.Recorded = r.recordedMounts(devices)
		sample := base
		sample.Devices = &devices
		if err := appendReport(sample); err != nil {
			return nil, err
		}
	}
	roots, err := p.NodeStorage(v.State)
	if err != nil {
		return nil, err
	}
	for _, root := range roots.Roots() {
		if root.Definition.Key != r.Identity.Public || root.Attestation == nil || root.Closed != nil {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// The existing RootManager checks the registered directory identity.
		if r.nodeRoots == nil {
			continue
		}
		if _, e := r.nodeRoots.Space(ctx, root); e != nil {
			continue
		}
		disk, e := observability.InspectDisk(ctx, base.Node, root.Definition.Path)
		if e != nil {
			continue
		}
		disk.Source, disk.RootID = "root/"+root.Definition.ID, root.Definition.ID
		disk.RootGeneration, disk.RootRevision = root.Generation, root.Revision
		sample := base
		sample.Disk = &disk
		if err := appendReport(sample); err != nil {
			return nil, err
		}
	}
	for _, peerEntry := range d.Entries {
		if peerEntry.Peer.ID == base.Node || !membership.FullMember(peerEntry) {
			continue
		}
		key, e := identity.ParseKey(peerEntry.CurrentPeer().Key)
		if e != nil {
			return nil, e
		}
		peer, known := r.Mesh.Peer(sfcp.Identity(key))
		if !known {
			continue
		}
		if link, known := r.Mesh.LinkObservation(base.Node, peer); known {
			sample := base
			sample.Link = &link
			if err := appendReport(sample); err != nil {
				return nil, err
			}
		}
	}
	if consensus, e := r.Engine().ConsensusObservation(ctx); e != nil {
		log.Printf("node observation dropped: node=%s source=consensus reason=unavailable error=%v", base.Node, e)
	} else {
		if !entry.Peer.Voter && consensus.Role == "follower" {
			consensus.Role = "non-voter"
		}
		sample := base
		sample.Consensus = &consensus
		if err := appendReport(sample); err != nil {
			return nil, err
		}
	}
	usage, err := r.collectTenantUsage(ctx, v, base.Node)
	if err != nil {
		return out, err
	}
	for _, u := range usage {
		sample := base
		sample.Usage = &u
		if err := appendReport(sample); err != nil {
			return nil, err
		}
	}
	// Reuse the exact most recent owner inspection, without converting its
	// process state into lifecycle permission or synthesizing a fresh timestamp.
	stored, err := r.nodeObservations(ctx, v)
	if err != nil {
		return out, err
	}
	for _, report := range stored {
		if report.Node == base.Node && report.RegistryPull != nil {
			sample := base
			pull := *report.RegistryPull
			sample.RegistryPull = &pull
			if err := appendReport(sample); err != nil {
				return out, err
			}
			continue
		}
		if report.Node == base.Node && report.Task != nil && report.Index <= v.State.Index() && observability.Fresh(report.At, uint64(time.Now().UnixMilli())) {
			raw, err := json.Marshal(report)
			if err != nil {
				return out, err
			}
			out = append(out, raw)
		}
	}
	for _, u := range r.volumeUsageSamples(ctx, v, p, base.Node, stored) {
		sample := base
		sample.Volume = &u
		if err := appendReport(sample); err != nil {
			return out, err
		}
	}
	return out, nil
}

func (r *Runtime) publishTaskMeasurement(v cluster.View, app control.AppView, stage deployment.StageRecord, status workload.ContainerStatus) error {
	if status.TaskFact == nil || stage.Result == nil || stage.Command == nil {
		return nil
	}
	task := observability.Task{Tenant: app.Tenant, App: app.App, Deployment: app.Deployment, Key: stage.Command.Key, Native: status.NativeID, Generation: stage.Result.Generation, Revision: stage.Result.Revision, Fact: status.TaskFact.Clone(), StartedAt: status.StartedAt}
	if status.Exit != nil {
		code := int64(status.Exit.Code)
		task.ExitCode = &code
	}
	// The native facts belong to the exact original Task above. Publication
	// belongs to the current logical daemon: a retained native owner neither
	// authenticates with its old key nor publishes into its historical DB.
	publisher := r
	if r.parentRuntime != nil {
		publisher = r.parentRuntime
	}
	signer := publisher.commandIdentity()
	report := observability.Report{Kind: "node-observation", Schema: 1, Cluster: r.controlPolicy.Cluster, Node: publisher.Engine().ObservedNodeID(), Key: signer.Public, Index: v.State.Index(), At: uint64(time.Now().UnixMilli()), Task: &task}
	report.Signature = ed25519.Sign(signer.Private, observability.SigningBytes(report))
	raw, err := json.Marshal(report)
	if err != nil {
		return err
	}
	return publisher.storeNodeObservation(sfcp.Identity(signer.Public), raw)
}

// observationResend is how long an unchanged report waits before it is sent
// to a peer again. Receivers treat reports older than observability.MaxAge
// (120s) as stale, so an unchanged one must still arrive within that.
const observationResend = 60 * time.Second

type observationSentAt struct {
	digest [32]byte
	at     time.Time
}

// observationDigest identifies a report's content apart from when it was
// taken, the index it was taken at and its signature.
func observationDigest(raw []byte) (string, [32]byte, bool) {
	report, err := observability.Decode(raw)
	if err != nil {
		return "", [32]byte{}, false
	}
	report.At, report.Index, report.Signature = 0, 0, nil
	return report.Source(), sha256.Sum256(observability.SigningBytes(report)), true
}

// observationDue reports whether peer needs report b: its content changed,
// it was last sent observationResend ago, or the link to peer broke since.
func observationDue(last observationSentAt, known bool, digest [32]byte, linkedSince time.Time, linked bool, now time.Time) bool {
	return !known || last.digest != digest || now.Sub(last.at) >= observationResend || !linked || linkedSince.After(last.at)
}

// errObservationsNotReady: this node's committed view does not list it as a
// member yet (just after a join, before the entry is applied here), so it has
// nothing it may report. The loop says so once, not every round.
var errObservationsNotReady = errors.New("this node is not a member in its committed view yet")

// observationInterval is how often a node collects and sends its reports.
var observationInterval = 30 * time.Second

func (r *Runtime) managedObservationLoop() {
	tick := time.NewTicker(observationInterval)
	defer tick.Stop()
	waiting := false
	for {
		ctx, cancel := context.WithTimeout(r.ctx, 30*time.Second)
		v, err := r.Engine().Read(ctx, false)
		var raw [][]byte
		if err == nil {
			raw, err = r.collectNodeObservations(ctx, v)
		}
		if notReady := errors.Is(err, errObservationsNotReady); notReady != waiting {
			waiting = notReady
			if notReady {
				log.Printf("node observations waiting: %v", err)
			} else {
				log.Printf("node observations resumed")
			}
		}

		// One report that cannot be stored is dropped alone, with a log
		// line; the reports after it are still stored and sent.
		allStored := make([][]byte, 0, len(raw))
		for _, b := range raw {
			if writeErr := r.storeNodeObservation(sfcp.Identity(r.Identity.Public), b); writeErr != nil {
				source, _, _ := observationDigest(b)
				log.Printf("node observation dropped: source=%s reason=local-store error=%v", source, writeErr)
				err = errors.Join(err, writeErr)
				continue
			}
			allStored = append(allStored, b)
		}
		if len(allStored) != 0 {
			d, directoryErr := r.controlPolicy.Members(v.State)
			if directoryErr == nil {
				if r.observationSent == nil {
					r.observationSent = map[[32]byte]map[string]observationSentAt{}
				}
				now := time.Now()
				type delivery struct {
					sources []string
					digests [][32]byte
					sent    []bool
				}
				deliveries := map[[32]byte]*delivery{}
				var deliveriesMu sync.Mutex
				var workers sync.WaitGroup
				slots := make(chan struct{}, 4)
				for _, entry := range d.Entries {
					key, keyErr := identity.ParseKey(entry.CurrentPeer().Key)
					if keyErr != nil || key == r.Identity.Public || !membership.FullMember(entry) {
						continue
					}
					peer, known := r.Mesh.Peer(sfcp.Identity(key))
					if !known {
						continue
					}
					sent := r.observationSent[key]
					linkedSince, linked := r.Mesh.ConnectedSince(sfcp.Identity(key))
					due := &delivery{}
					var stored [][]byte
					for _, b := range allStored {
						source, digest, ok := observationDigest(b)
						last, seen := sent[source]
						if ok && !observationDue(last, seen, digest, linkedSince, linked, now) {
							continue
						}
						stored = append(stored, b)
						due.sources, due.digests = append(due.sources, source), append(due.digests, digest)
						if !ok {
							due.digests[len(due.digests)-1] = [32]byte{}
						}
					}
					if len(stored) == 0 {
						continue
					}
					deliveries[key] = due
					workers.Add(1)
					go func() {
						defer workers.Done()
						select {
						case slots <- struct{}{}:
						case <-ctx.Done():
							return
						}
						defer func() { <-slots }()
						call, stop := context.WithTimeout(ctx, 2*time.Second)
						session, sendErr := r.Mesh.Dial(call, peer)
						stop()
						sent := make([]bool, len(stored))
						if sendErr != nil {
							log.Printf("node observations not sent: peer=%s reports=%d error=%v", peer.ID, len(stored), sendErr)
						} else {
							// One frame carries as many reports as fit. A
							// report the peer refuses is dropped alone.
							call, stop := context.WithTimeout(ctx, 2*time.Second)
							accepted, e := session.ReportBatch(call, sfcp.KindNodeObservation, stored)
							stop()
							copy(sent, accepted)
							if e != nil {
								sendErr = e
								log.Printf("node observations not sent: peer=%s reports=%d error=%v", peer.ID, len(stored), e)
							}
							for i, ok := range accepted {
								if !ok && e == nil {
									sendErr = sfcp.ErrReportRefused
									log.Printf("node observation dropped: peer=%s source=%s reason=refused", peer.ID, due.sources[i])
								}
							}
						}
						r.mu.Lock()
						if sendErr == nil {
							delete(r.deliveryErrors, peer.ID)
						} else {
							r.deliveryErrors[peer.ID] = sendErr.Error()
						}
						r.mu.Unlock()
						deliveriesMu.Lock()
						due.sent = sent
						deliveriesMu.Unlock()
					}()
				}
				workers.Wait()
				for key, due := range deliveries {
					if r.observationSent[key] == nil {
						r.observationSent[key] = map[string]observationSentAt{}
					}
					for i, source := range due.sources {
						if i < len(due.sent) && due.sent[i] && due.digests[i] != ([32]byte{}) {
							r.observationSent[key][source] = observationSentAt{digest: due.digests[i], at: now}
						} else {
							delete(r.observationSent[key], source)
						}
					}
				}
			} else {
				err = errors.Join(err, directoryErr)
			}
		}
		if err != nil && !waiting {
			log.Printf("node observation round incomplete: %v", err)
		}
		r.mu.Lock()
		r.reportError = err
		r.mu.Unlock()
		cancel()
		select {
		case <-r.ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// Container metrics reuse the existing Docker stats summarizer. Counts are
// authenticated owner inspections; inability to inspect is explicitly partial.
func (r *Runtime) collectTenantUsage(ctx context.Context, v cluster.View, node string) ([]observability.Usage, error) {
	resources, err := r.controlPolicy.Resources(v.State)
	if err != nil {
		return nil, err
	}
	usage := map[string]observability.Usage{}
	for _, limit := range resources.Quotas.Limits() {
		if limit.Node == node && limit.Tenant != "" {
			zeroCPU, zeroMemory := uint64(0), uint64(0)
			usage[limit.Tenant] = observability.Usage{Tenant: limit.Tenant, Complete: r.docker != nil, CPUUsed: &zeroCPU, MemoryUsed: &zeroMemory}
		}
	}
	if r.docker == nil {
		out := []observability.Usage{}
		for _, u := range usage {
			u.CPUUsed, u.MemoryUsed = nil, nil
			out = append(out, u)
		}
		return out, nil
	}
	listed, err := r.docker.API.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: client.Filters{}.Add("label", "org.sfc.owner="+r.owner)})
	if err != nil {
		return nil, err
	}
	nextCPU := map[string]observedContainerCPU{}
	for _, item := range listed.Items {
		key := item.Labels["org.sfc.key"]
		parts := strings.Split(key, "/")
		if len(parts) != 5 || parts[0] != "workload" || parts[1] != "task" {
			continue
		}
		var goal deployment.GoalCommand
		object := v.State.Object(key)
		if !object.Present || json.Unmarshal([]byte(object.Value), &goal) != nil || goal.Node != node || goal.Tenant != parts[2] {
			if u, known := usage[parts[2]]; known {
				u.Complete = false
				usage[u.Tenant] = u
			}
			continue
		}
		u := usage[goal.Tenant]
		u.Tenant = goal.Tenant
		if r.workload == nil {
			u.Complete = false
			usage[u.Tenant] = u
			continue
		}
		native, running, e := r.workload.NativeIdentity(ctx, key)
		if e != nil || native != item.ID {
			u.Complete = false
			usage[u.Tenant] = u
			continue
		}
		u.Containers++
		actual, inspectErr := r.docker.API.ContainerInspect(ctx, item.ID, client.ContainerInspectOptions{})
		if inspectErr != nil || actual.Container.State == nil {
			u.Complete = false
			usage[u.Tenant] = u
			continue
		}
		unhealthy := actual.Container.State.Health != nil && string(actual.Container.State.Health.Status) == "unhealthy"
		if (!running && (goal.Lifecycle == nil || !goal.Lifecycle.Drain)) || actual.Container.State.Restarting || unhealthy {
			u.Problems++
		}
		if !running {
			if u.CPUUsed == nil && u.Containers == 1 {
				n := uint64(0)
				u.CPUUsed = &n
			}
			if u.MemoryUsed == nil && u.Containers == 1 {
				n := uint64(0)
				u.MemoryUsed = &n
			}
			usage[u.Tenant] = u
			continue
		}
		stats, e := r.docker.API.ContainerStats(ctx, item.ID, client.ContainerStatsOptions{})
		if e != nil {
			u.CPUUsed, u.MemoryUsed = nil, nil
			usage[u.Tenant] = u
			continue
		}
		var sample container.StatsResponse
		e = json.NewDecoder(io.LimitReader(stats.Body, 128<<10)).Decode(&sample)
		closeErr := stats.Body.Close()
		if e != nil || closeErr != nil {
			u.CPUUsed, u.MemoryUsed = nil, nil
			usage[u.Tenant] = u
			continue
		}
		if old, known := r.observationContainers[item.ID]; known && !sample.Read.IsZero() {
			sample.PreRead, sample.PreCPUStats = old.At, old.CPU
		}
		if !sample.Read.IsZero() && !sample.Read.After(time.Now()) {
			nextCPU[item.ID] = observedContainerCPU{At: sample.Read, CPU: sample.CPUStats}
		}
		summary := containerops.Summarize(sample)
		if summary.CPUPercent == nil || math.IsNaN(*summary.CPUPercent) || *summary.CPUPercent < 0 || *summary.CPUPercent > float64(math.MaxUint64)/1e7 {
			u.CPUUsed = nil
		} else {
			n := uint64(*summary.CPUPercent * 1e7)
			if u.Containers == 1 {
				u.CPUUsed = &n
			} else if u.CPUUsed != nil && n <= math.MaxUint64-*u.CPUUsed {
				total := *u.CPUUsed + n
				u.CPUUsed = &total
			} else {
				u.CPUUsed = nil
			}
		}
		memory := summary.MemoryWorkingSetBytes
		if memory == nil {
			memory = summary.MemoryBytes
		}
		if memory == nil {
			u.MemoryUsed = nil
		} else if u.Containers == 1 {
			n := *memory
			u.MemoryUsed = &n
		} else if u.MemoryUsed != nil && *memory <= math.MaxUint64-*u.MemoryUsed {
			n := *u.MemoryUsed + *memory
			u.MemoryUsed = &n
		} else {
			u.MemoryUsed = nil
		}
		usage[u.Tenant] = u
	}
	r.observationContainers = nextCPU
	keys := make([]string, 0, len(usage))
	for key := range usage {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	out := make([]observability.Usage, 0, len(keys))
	for _, key := range keys {
		u := usage[key]
		if !u.Complete {
			u.CPUUsed, u.MemoryUsed = nil, nil
		}
		out = append(out, u)
	}
	return out, ctx.Err()
}

// buildCapability is what this server's Host observation says about image
// builds. Today's Docker engine always offers build containers, so only the
// workload module decides; a Seafield engine also reports its build API.
func (r *Runtime) buildCapability() *observability.Build {
	if r.imageBuildNative == nil {
		return &observability.Build{Reason: "WORKLOAD_OFF"}
	}
	return &observability.Build{Enabled: true}
}
