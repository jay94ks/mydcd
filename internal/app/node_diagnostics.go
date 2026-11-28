// SPDX-License-Identifier: Apache-2.0

package app

import (
	"archive/tar"
	"bytes"
	"cmp"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/eventlog"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// Diagnostic logs are the existing allowlisted sfcd event journal. Raw error
// strings, operator reasons, process output, environment, credentials and keys
// never enter the archive; filtering occurs before JSON/archive serialization.
type nodeDiagnosticLog struct {
	At                                                   uint64
	Kind, Scope, Node, Tenant, App, Service, Code, State string
}

func diagnosticLogs(items []eventlog.Item) []nodeDiagnosticLog {
	rows := make([]nodeDiagnosticLog, 0, len(items))
	for _, item := range items {
		e := item.Event
		rows = append(rows, nodeDiagnosticLog{At: e.At, Kind: e.Kind, Scope: e.Scope, Node: e.Target.Node, Tenant: e.Target.Tenant, App: e.Target.App, Service: e.Target.Service, Code: e.Detail.Code, State: e.Detail.State})
	}
	return rows
}

// diagnosticProfile is one Go runtime profile (pprof protobuf, already
// gzip-compressed by the runtime). It holds code locations and sample counts
// only: no arguments, memory contents, environment or labels.
type diagnosticProfile struct {
	name string
	data []byte
}

// packNodeDiagnostics writes the JSON members and then as many profiles as
// fit the bundle budgets, in order; a profile that does not fit is left out
// and the bundle is marked truncated.
// omitted holds control.NodeDiagnosticsOmissions codes for what the bundle
// leaves out; a dropped profile adds its own.
func packNodeDiagnostics(node string, at time.Time, config, status any, logs []nodeDiagnosticLog, omitted []string, profiles ...diagnosticProfile) (control.NodeDiagnosticsBundle, error) {
	result, err := packNodeDiagnosticFiles(node, at, config, status, logs, omitted, profiles)
	for err == errDiagnosticsBudget && len(profiles) > 0 {
		dropped := profiles[len(profiles)-1]
		profiles = profiles[:len(profiles)-1]
		omitted = append(slices.Clone(omitted), strings.TrimSuffix(dropped.name, ".pb.gz"))
		result, err = packNodeDiagnosticFiles(node, at, config, status, logs, omitted, profiles)
	}
	return result, err
}

var errDiagnosticsBudget = errors.New("node diagnostics budget exceeded")

func packNodeDiagnosticFiles(node string, at time.Time, config, status any, logs []nodeDiagnosticLog, omitted []string, profiles []diagnosticProfile) (control.NodeDiagnosticsBundle, error) {
	result := control.NodeDiagnosticsBundle{Schema: 1, Node: node, Format: "tar+gzip", CreatedAt: at.UTC().Format(time.RFC3339), LimitBytes: control.NodeDiagnosticsMaxBytes, ExpandedLimitBytes: control.NodeDiagnosticsExpandedBytes, Truncated: len(omitted) > 0, Omitted: omitted}
	type member struct {
		name string
		raw  []byte
	}
	files := []member{}
	for _, file := range []struct {
		name  string
		value any
	}{{"config-summary.json", config}, {"status.json", status}, {"sfcd-events.json", logs}} {
		raw, err := json.Marshal(file.value)
		if err != nil {
			return result, err
		}
		files = append(files, member{file.name, raw})
	}
	for _, p := range profiles {
		files = append(files, member{p.name, p.data})
	}
	var output bytes.Buffer
	zip := gzip.NewWriter(&output)
	archive := tar.NewWriter(zip)
	total := 0
	for _, file := range files {
		raw := file.raw
		total += len(raw)
		if total > control.NodeDiagnosticsExpandedBytes {
			return result, errDiagnosticsBudget
		}
		if err := archive.WriteHeader(&tar.Header{Name: file.name, Mode: 0600, Size: int64(len(raw)), ModTime: at.UTC(), Typeflag: tar.TypeReg}); err != nil {
			return result, err
		}
		if _, err := archive.Write(raw); err != nil {
			return result, err
		}
	}
	if err := archive.Close(); err != nil {
		return result, err
	}
	if err := zip.Close(); err != nil {
		return result, err
	}
	if output.Len() > control.NodeDiagnosticsMaxBytes {
		return result, errDiagnosticsBudget
	}
	result.Data = output.Bytes()
	result.Bytes = uint64(len(result.Data))
	result.Digest = sha256.Sum256(result.Data)
	return result, nil
}
func (r *Runtime) nodeDiagnostics(ctx context.Context, read control.NodeDiagnosticsRead) (control.NodeDiagnosticsBundle, error) {
	if read.Owner == r.Identity.Public {
		return r.nodeDiagnosticsLocal(ctx, read)
	}
	peer, ok := r.Mesh.Peer(sfcp.Identity(read.Owner))
	if !ok || !peer.Member || peer.ID != read.Node {
		return control.NodeDiagnosticsBundle{}, sfcp.ErrAdmission
	}
	raw, _ := json.Marshal(read)
	reply, err := cluster.CallManagement(ctx, r.Mesh, r.Identity, r.controlPolicy.Cluster, peer, cluster.ManagementRequest{Method: "node-diagnostics-owner", Input: raw})
	if err != nil {
		return control.NodeDiagnosticsBundle{}, err
	}
	bundle, err := schema.Decode[control.NodeDiagnosticsBundle](reply.Data)
	if err != nil || !bundle.Valid(read.Node) {
		return bundle, sfcp.ErrAdmission
	}
	return bundle, nil
}

// currentNodeRead rechecks a diagnostics-class read (diagnostics, node
// logs) on this owner: the current user at a quorum barrier, including a
// relayed call. A formerly approved read is not a lasting grant.
func (r *Runtime) currentNodeRead(ctx context.Context, read control.NodeDiagnosticsRead) (control.NodeDiagnosticsRead, cluster.View, error) {
	if r.installation == nil || read.Owner != r.Identity.Public || read.Node != r.installation.record.Root.Self.ID {
		return control.NodeDiagnosticsRead{}, cluster.View{}, sfcp.ErrAdmission
	}
	raw, _ := json.Marshal(read)
	permit, err := r.appCall(ctx, "node-diagnostics-permit", raw)
	if err != nil {
		return control.NodeDiagnosticsRead{}, cluster.View{}, err
	}
	current, err := schema.Decode[control.NodeDiagnosticsRead](permit.Data)
	if err != nil || current.Node != read.Node || current.Owner != r.Identity.Public || !bytes.Equal(access.SessionBytes(current.Session), access.SessionBytes(read.Session)) || !bytes.Equal(current.Session.Signature, read.Session.Signature) {
		return control.NodeDiagnosticsRead{}, cluster.View{}, sfcp.ErrAdmission
	}
	view, err := r.Engine().ReadAtLeast(ctx, current.Index)
	if err != nil {
		return control.NodeDiagnosticsRead{}, cluster.View{}, err
	}
	// ReadAtLeast legitimately returns a local durable prefix. Its barrier,
	// epoch and the current authorization/owner are the required checks.
	live, err := r.controlPolicy.ReadNodeDiagnostics(view.State, current.Session, time.Now().Unix(), current.Node)
	if err != nil || view.State.Index() < current.Index || view.State.ModuleEpoch() != current.Epoch || live.Owner != current.Owner || live.MembersRoot != current.MembersRoot {
		return control.NodeDiagnosticsRead{}, cluster.View{}, sfcp.ErrAdmission
	}
	return current, view, nil
}

func (r *Runtime) nodeDiagnosticsLocal(ctx context.Context, read control.NodeDiagnosticsRead) (control.NodeDiagnosticsBundle, error) {
	current, view, err := r.currentNodeRead(ctx, read)
	if err != nil {
		return control.NodeDiagnosticsBundle{}, err
	}
	// Profiles are taken after the permit and before any runtime lock, so a
	// long CPU profile never holds back shutdown or other reads.
	profiles, profileErr := diagnosticProfiles(ctx, read.CPUProfileSeconds)
	if profileErr != nil {
		return control.NodeDiagnosticsBundle{}, profileErr
	}
	now := time.Now().UTC()
	d, err := r.controlPolicy.Members(view.State)
	if err != nil {
		return control.NodeDiagnosticsBundle{}, err
	}
	node, found := d.NodeView(read.Node)
	if !found {
		return control.NodeDiagnosticsBundle{}, sfcp.ErrAdmission
	}
	logs := []nodeDiagnosticLog{}
	r.life.RLock()
	defer r.life.RUnlock()
	if r.closed {
		return control.NodeDiagnosticsBundle{}, sfcp.ErrAdmission
	}
	unavailable, older, gap := false, false, false
	for _, owner := range append([]*Runtime{r}, r.nativeOwners...) {
		if owner != r {
			owner.life.RLock()
		}
		if owner.closed || owner.events == nil {
			unavailable = true
			if owner != r {
				owner.life.RUnlock()
			}
			continue
		}
		page, e := owner.events.Page(eventlog.Query{Node: read.Node, Limit: 100}, uint64(now.UnixMilli()), func(row eventlog.Record) bool { return row.SourceNode == read.Node })
		if owner != r {
			owner.life.RUnlock()
		}
		if e != nil {
			return control.NodeDiagnosticsBundle{}, e
		}
		logs = append(logs, diagnosticLogs(page.Items)...)
		older, gap = older || page.More, gap || page.Incomplete
	}
	slices.SortFunc(logs, func(a, b nodeDiagnosticLog) int { return cmp.Compare(a.At, b.At) })
	if len(logs) > 100 {
		logs = logs[len(logs)-100:]
		older = true
	}
	omitted := []string{}
	for _, o := range []struct {
		on   bool
		code string
	}{{gap, "events-gap"}, {older, "events-older"}, {unavailable, "events-unavailable"}} {
		if o.on {
			omitted = append(omitted, o.code)
		}
	}
	config := struct {
		Schema                              uint8
		Node, Endpoint                      string
		Managed, Network, Workload, Ingress bool
	}{1, read.Node, r.installation.record.CurrentListen(), true, r.networkEnabled, r.workload != nil, r.ingress != nil}
	status := struct {
		Schema                                    uint8
		Index, MembersRoot, ConfigurationIndex    uint64
		Node, Phase                               string
		Voter, Cordoned, AdmitsWork, NativeClosed bool
	}{1, current.Index, current.MembersRoot, nodeConfigurationIndex(d), read.Node, string(node.Node.Phase), node.Node.Member.Voter, node.Scheduling.Enabled, node.AdmitsWork, node.Node.Closure != nil && node.Node.Closure.Closed}
	return packNodeDiagnostics(read.Node, now, config, status, logs, omitted, profiles...)
}

func nodeConfigurationIndex(d membership.Directory) uint64 {
	topology, err := d.Topology()
	if err != nil {
		return 0
	}
	return topology.Configuration().Index
}
