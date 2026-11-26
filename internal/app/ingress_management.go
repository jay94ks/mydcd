// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"github.com/jay94ks/mydcd/internal/certstore"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/ingress"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/schema"
	"slices"
	"time"
)

func (r *Runtime) applyIngressBlocks(ctx context.Context, v cluster.View) error {
	if r.ingress == nil {
		return nil
	}
	book, err := r.controlPolicy.IngressManagement(v.State)
	if err != nil {
		return err
	}
	users, err := r.controlPolicy.Catalog(v.State)
	if err != nil {
		return err
	}
	for _, tenant := range users.Tenants() {
		if err = r.ingress.SetTenantPolicy(tenant.ID, book.HostPolicy(tenant.ID)); err != nil {
			return err
		}
	}
	certificates, err := r.controlPolicy.Certificates(v.State)
	if err != nil {
		return err
	}
	responder := ""
	if certificates.ACMEResponder != nil {
		responder = certificates.ACMEResponder.Address
	}
	domains := slices.Clone(certificates.Domains)
	covers := func(host string) bool {
		return slices.ContainsFunc(domains, func(d certstore.Domain) bool { return certstore.DomainCovers(d.Name, host) })
	}
	if err = r.ingress.SetACMEResponder(responder, covers); err != nil {
		return err
	}
	if err = r.ingress.SetBlocks(book.Revision, r.Engine().ObservedNodeID(), book.ConfiguredBlocks(), uint64(time.Now().Unix())); err != nil {
		return err
	}
	if err = r.ingress.SetRuntimeControls(book.Revision, book.Controls(r.Engine().ObservedNodeID())); err != nil {
		return err
	}
	if gateways, found := book.NodeGateways(r.Engine().ObservedNodeID()); found {
		return r.ingress.UpdateGateways(ctx, gateways.Configuration, gateways.Revision)
	}
	return nil
}

func (r *Runtime) observeIngressOwner(ctx context.Context, read control.IngressRead) (control.IngressPage, error) {
	view, err := r.currentView(ctx)
	if err != nil || view.Local {
		return control.IngressPage{}, mydcp.ErrAdmission
	}
	page, err := r.controlPolicy.IngressPage(view.State, read.Session, time.Now().Unix(), read.Query)
	if err != nil {
		return page, err
	}
	r.life.RLock()
	defer r.life.RUnlock()
	if r.closed {
		return page, mydcp.ErrAdmission
	}
	if read.Query.Part == "gateways" {
		if !page.System || len(page.NodeGateways) != 1 || read.Query.Node != r.Engine().ObservedNodeID() {
			return page, mydcp.ErrAdmission
		}
		gateway := &page.NodeGateways[0]
		if r.ingress == nil {
			gateway.Error = "MODULE_DISABLED"
			return page, nil
		}
		actual, applied, cause := r.ingress.GatewayConfiguration()
		gateway.AppliedRevision, gateway.Error = applied, cause
		if gateway.Source == "file" {
			gateway.Configuration = actual
		}
		if check := read.Query.Check; check != nil {
			desired := control.MergeNodeGateways(gateway.Configuration, check.External, check.Local)
			if ingress.ValidateLocalGateways(desired) != nil {
				page.GatewayCheckError = "Invalid: INGRESS_ADDRESS_OR_CONFIGURATION_INVALID"
				return page, nil
			}
			evidence := control.NodeGatewaysEvidence{Cluster: r.controlPolicy.Cluster, Reporter: r.Identity.Public, Node: check.Node, Request: check.Request, User: read.Session.User, Key: read.Session.Key, Epoch: view.State.ModuleEpoch(), Expected: check.Expected, At: time.Now().Unix(), Previous: ingress.NormalizeGatewayConfiguration(gateway.Configuration), Configuration: desired}
			evidence.Signature = ed25519.Sign(r.Identity.Private, control.NodeGatewaysEvidenceBytes(evidence))
			page.GatewayEvidence = &evidence
		}
		page.Nodes[0].Configuration = gateway
		return page, nil
	}
	summaryQuery := read.Query
	if read.SummaryQuery != nil {
		summaryQuery = *read.SummaryQuery
		if !summaryQuery.Valid() || summaryQuery.Node != r.Engine().ObservedNodeID() || summaryQuery.Tenant != read.Query.Tenant || summaryQuery.App != read.Query.App {
			return page, mydcp.ErrAdmission
		}
	}
	summaryQuery.Node = r.Engine().ObservedNodeID()
	summaryQuery.Key = ""
	summaryQuery.After = ""
	summaryQuery.Offset = 0
	summaryQuery.Part = "mappings"
	summary, err := r.controlPolicy.IngressPage(view.State, read.Session, time.Now().Unix(), summaryQuery)
	if err != nil {
		return page, err
	}
	if read.Query.Part != "blocks" {
		page.Nodes = summary.Nodes
	}
	enabled := r.ingress != nil
	for i := range page.Nodes {
		sum := &page.Nodes[i]
		sum.Enabled = &enabled
		if page.System && r.ingress != nil {
			book, e := r.controlPolicy.IngressManagement(view.State)
			if e != nil {
				return page, e
			}
			actual, applied, cause := r.ingress.GatewayConfiguration()
			configuration := control.NodeGatewaysView{Node: sum.Node, Source: "file", Configuration: actual, AppliedRevision: applied, Error: cause}
			if stored, found := book.NodeGateways(sum.Node); found {
				configuration.Source, configuration.Configuration, configuration.Revision = "cluster", stored.Configuration, stored.Revision
			}
			sum.Configuration = &configuration
		}
		if r.ingress != nil {
			visible := map[string]bool{}
			for _, ref := range summary.SummaryRefs {
				goal := view.State.Object(ref.Key)
				if !goal.Present {
					continue
				}
				var command deployment.GoalCommand
				if json.Unmarshal([]byte(goal.Value), &command) == nil {
					visible[command.Tenant+"\x00"+command.App] = true
				}
			}
			byGateway := map[string]control.IngressGatewaySummary{}
			for _, g := range r.ingress.Gateways() {
				entry := byGateway[g.Gateway]
				entry.Gateway = g.Gateway
				if page.System {
					entry.Unmatched += g.Unmatched
					entry.SourceRejected += g.SourceRejected
				}
				// Page shared listener/host bindings as one bounded sequence.
				// Repeat the listener's public address with its selected hosts;
				// no unselected tenant appears in a node-only query.
				add := func(host *ingress.SharedHostObservation) {
					index := entry.BindingsTotal
					entry.BindingsTotal++
					if index < int(read.Query.Offset) || index >= int(read.Query.Offset)+4 {
						return
					}
					row := g
					row.Hosts = nil
					if !page.System {
						row.SourceRejected, row.Unmatched = 0, 0
					}
					if host != nil {
						row.Hosts = []ingress.SharedHostObservation{*host}
					}
					entry.Listeners = append(entry.Listeners, row)
				}
				if len(g.Hosts) == 0 && page.System {
					add(nil)
				}
				for _, host := range g.Hosts {
					if page.System || visible[host.Tenant+"\x00"+host.App] {
						add(&host)
					}
				}
				entry.Offset = read.Query.Offset
				if int(read.Query.Offset)+4 < entry.BindingsTotal {
					entry.Next = read.Query.Offset + 4
				}
				byGateway[g.Gateway] = entry
			}
			for _, kind := range []string{"external", "local"} {
				if entry, ok := byGateway[kind]; ok {
					if page.System || entry.BindingsTotal > 0 {
						sum.Gateways = append(sum.Gateways, entry)
					}
				}
			}
		}
		for _, ref := range summary.SummaryRefs {
			if ref.Node != sum.Node {
				continue
			}
			if r.ingress == nil {
				continue
			}
			snapshot, found := r.ingress.Snapshot(ref.Key, uint64(time.Now().UnixMilli()))
			if !found || snapshot.Generation != ref.Generation {
				sum.Connections = -1
				sum.Requests = -1
				break
			}
			sum.Connections += snapshot.Connections
			sum.Requests += snapshot.Requests
		}
	}

	if read.Query.Part == "blocks" {
		for i := range page.Blocks {
			if r.ingress == nil {
				continue
			}
			for _, actual := range r.ingress.BlockApplications() {
				if actual.ID == page.Blocks[i].Block.ID && actual.Node == r.Engine().ObservedNodeID() {
					page.Blocks[i].Applications = append(page.Blocks[i].Applications, actual)
				}
			}
		}
	}
	for at := range page.Mappings {
		row := &page.Mappings[at]
		if row.Owner != r.Identity.Public || row.Node != r.Engine().ObservedNodeID() {
			return control.IngressPage{}, mydcp.ErrAdmission
		}
		if r.ingress == nil {
			row.Error = "MODULE_DISABLED"
			continue
		}
		snapshot, found := r.ingress.Snapshot(row.Key, uint64(time.Now().UnixMilli()))
		if !found {
			row.Error = "NOT_OBSERVED"
			continue
		}
		if snapshot.Generation != row.Generation {
			row.Error = "GENERATION_PENDING"
			continue
		}
		visibleBlocks := map[string]bool{}
		for _, b := range row.Blocks {
			visibleBlocks[b.Block.ID] = true
		}
		visibleApplications := snapshot.Blocks[:0]
		for _, b := range snapshot.Blocks {
			if visibleBlocks[b.ID] {
				visibleApplications = append(visibleApplications, b)
			}
		}
		snapshot.Blocks = visibleApplications
		row.Runtime = &snapshot
		row.Ready, row.Draining, row.Error, row.ObservedAt = snapshot.Ready, snapshot.Draining, snapshot.Error, snapshot.ObservedAt
		if read.Query.Part != "metrics" && read.Query.Part != "errors" {
			row.Runtime.Metrics = ingress.Metrics{}
		}
	}
	for i := range page.Mappings {
		pageIngressMapping(&page.Mappings[i], read.Query)
	}
	latest, err := r.currentView(ctx)
	if err != nil || latest.Local {
		return control.IngressPage{}, mydcp.ErrAdmission
	}
	current, err := r.controlPolicy.IngressPage(latest.State, read.Session, time.Now().Unix(), read.Query)
	if err != nil || !page.SameSelection(current) {
		return control.IngressPage{}, mydcp.ErrAdmission
	}
	raw, _ := json.Marshal(page)
	if len(raw) > 112<<10 {
		return control.IngressPage{}, fmt.Errorf("ingress page exceeds response budget")
	}
	return page, nil
}
func (r *Runtime) readIngresses(ctx context.Context, read control.IngressRead) (control.IngressPage, error) {
	view, err := r.currentView(ctx)
	if err != nil || view.Local {
		return control.IngressPage{}, mydcp.ErrAdmission
	}
	page, err := r.controlPolicy.IngressPage(view.State, read.Session, time.Now().Unix(), read.Query)
	if err != nil {
		return page, err
	}
	if read.Query.Part == "history" {
		return page, nil
	}
	if len(page.Mappings) == 0 && read.Query.Node != "" && len(page.Nodes) == 1 {
		owner := page.Nodes[0].Owner
		var actual control.IngressPage
		if owner == r.Identity.Public {
			actual, err = r.observeIngressOwner(ctx, read)
		} else {
			peer, known := r.Mesh.Peer(mydcp.Identity(owner))
			if !known {
				return page, nil
			}
			raw, _ := json.Marshal(read)
			reply, cause := cluster.CallManagement(ctx, r.Mesh, r.Identity, r.controlPolicy.Cluster, peer, cluster.ManagementRequest{Method: "ingress-observe", Input: raw})
			if cause != nil {
				return page, nil
			}
			actual, err = schema.Decode[control.IngressPage](reply.Data)
		}
		if err != nil {
			return page, nil
		}
		if actual.RootRevision != page.RootRevision {
			return control.IngressPage{}, mydcp.ErrAdmission
		}
		if read.Query.Part == "blocks" {
			page.Blocks = actual.Blocks
		}
		page.Nodes = actual.Nodes
		page.NodeGateways, page.GatewayEvidence, page.GatewayCheckError = actual.NodeGateways, actual.GatewayEvidence, actual.GatewayCheckError
	}
	for at := range page.Mappings {
		row := &page.Mappings[at]
		query := read
		query.Query.Key, query.Query.Node, query.Query.After = row.Key, row.Node, ""
		summaryQuery := read.Query
		summaryQuery.Node = row.Node
		query.SummaryQuery = &summaryQuery
		var actual control.IngressPage
		if row.Owner == r.Identity.Public {
			actual, err = r.observeIngressOwner(ctx, query)
		} else {
			peer, known := r.Mesh.Peer(mydcp.Identity(row.Owner))
			if !known {
				row.Error = "NODE_UNREACHABLE"
				continue
			}
			raw, _ := json.Marshal(query)
			reply, cause := cluster.CallManagement(ctx, r.Mesh, r.Identity, r.controlPolicy.Cluster, peer, cluster.ManagementRequest{Method: "ingress-observe", Input: raw})
			if cause != nil {
				row.Error = "NODE_UNREACHABLE"
				continue
			}
			actual, err = schema.Decode[control.IngressPage](reply.Data)
		}
		if err != nil {
			row.Error = "OBSERVATION_UNAVAILABLE"
			continue
		}
		if len(actual.Mappings) != 1 || actual.Mappings[0].Key != row.Key || actual.Mappings[0].Owner != row.Owner || actual.Mappings[0].Generation != row.Generation || actual.Mappings[0].Revision != row.Revision || actual.RootRevision != page.RootRevision {
			return control.IngressPage{}, mydcp.ErrAdmission
		}
		observed := actual.Mappings[0]
		*row = observed
		for i := range page.Nodes {
			for _, sum := range actual.Nodes {
				if sum.Node == page.Nodes[i].Node {
					page.Nodes[i] = sum
				}
			}
		}
	}
	for i := range page.Nodes {
		if page.Nodes[i].Enabled == nil {
			page.Nodes[i].Connections = -1
			page.Nodes[i].Requests = -1
		}
	}
	latest, err := r.currentView(ctx)
	if err != nil {
		return control.IngressPage{}, err
	}
	if latest.Local {
		return control.IngressPage{}, mydcp.ErrAdmission
	}
	current, err := r.controlPolicy.IngressPage(latest.State, read.Session, time.Now().Unix(), read.Query)
	if err != nil {
		return control.IngressPage{}, err
	}
	if !page.SameSelection(current) {
		return control.IngressPage{}, mydcp.ErrAdmission
	}
	for i := range page.Mappings {
		if page.Mappings[i].Error == "NODE_UNREACHABLE" || page.Mappings[i].Error == "OBSERVATION_UNAVAILABLE" {
			pageIngressMapping(&page.Mappings[i], read.Query)
		}
	}
	raw, _ := json.Marshal(page)
	if len(raw) > 112<<10 {
		return control.IngressPage{}, fmt.Errorf("ingress page exceeds response budget")
	}
	return page, nil
}

func pageIngressMapping(row *control.IngressMapping, q control.IngressQuery) {
	start := int(q.Offset)
	row.Offset = q.Offset
	row.ListenersTotal, row.RoutesTotal = len(row.Spec.Listeners), len(row.Spec.Routes)
	var all []ingress.BackendSpec
	for _, svc := range row.Spec.Services {
		all = append(all, svc.Backends...)
	}
	row.BackendsTotal = len(all)
	row.BlocksTotal = len(row.Blocks)
	if row.Runtime != nil {
		row.CertificatesTotal = len(row.Runtime.Certificates)
	}
	limit := max(row.ListenersTotal, row.RoutesTotal, row.BackendsTotal, row.BlocksTotal, row.CertificatesTotal)
	end := start + 4
	if end < limit {
		row.Next = uint32(end)
	}
	row.Spec.Listeners = slices.Clone(row.Spec.Listeners[min(start, len(row.Spec.Listeners)):min(end, len(row.Spec.Listeners))])
	row.Spec.Routes = slices.Clone(row.Spec.Routes[min(start, len(row.Spec.Routes)):min(end, len(row.Spec.Routes))])
	selected := map[string]bool{}
	for _, backend := range all[min(start, len(all)):min(end, len(all))] {
		selected[backend.ID] = true
	}
	var services []ingress.Service
	for _, svc := range row.Spec.Services {
		next := svc
		next.Backends = nil
		for _, backend := range svc.Backends {
			if selected[backend.ID] {
				next.Backends = append(next.Backends, backend)
			}
		}
		if len(next.Backends) > 0 {
			services = append(services, next)
		}
	}
	row.Spec.Services = services
	row.Blocks = slices.Clone(row.Blocks[min(start, len(row.Blocks)):min(end, len(row.Blocks))])
	if row.Runtime == nil {
		return
	}
	snapshot := row.Runtime
	snapshot.Certificates = slices.Clone(snapshot.Certificates[min(start, len(snapshot.Certificates)):min(end, len(snapshot.Certificates))])
	snapshot.Listeners = slices.Clone(snapshot.Listeners[min(start, len(snapshot.Listeners)):min(end, len(snapshot.Listeners))])
	snapshot.Backends = slices.Clone(snapshot.Backends[min(start, len(snapshot.Backends)):min(end, len(snapshot.Backends))])
	snapshot.Blocks = slices.Clone(snapshot.Blocks[min(start, len(snapshot.Blocks)):min(end, len(snapshot.Blocks))])
	metrics := &snapshot.Metrics
	if q.Part == "errors" {
		metrics.Routes, metrics.Backends, metrics.Gateways, metrics.Conditions = nil, nil, nil, nil
		size := len(metrics.Errors)
		metrics.Errors = slices.Clone(metrics.Errors[min(start, size):min(start+16, size)])
		row.Next = 0
		if start+16 < size {
			row.Next = uint32(start + 16)
		}
	} else if q.Part == "metrics" {
		metrics.Errors = nil
		maxItems := max(len(metrics.Routes), len(metrics.Backends), len(metrics.Gateways), len(metrics.Conditions))
		row.Next = 0
		if end < maxItems {
			row.Next = uint32(end)
		}
		metrics.Routes = slices.Clone(metrics.Routes[min(start, len(metrics.Routes)):min(end, len(metrics.Routes))])
		metrics.Backends = slices.Clone(metrics.Backends[min(start, len(metrics.Backends)):min(end, len(metrics.Backends))])
		metrics.Gateways = slices.Clone(metrics.Gateways[min(start, len(metrics.Gateways)):min(end, len(metrics.Gateways))])
		metrics.Conditions = slices.Clone(metrics.Conditions[min(start, len(metrics.Conditions)):min(end, len(metrics.Conditions))])
	}
}

func (r *Runtime) ingressReadModule(ctx context.Context, key string, input []byte) ([]byte, error) {
	caller, err := identity.ParseKey(key)
	if err != nil {
		return nil, mydcp.ErrAdmission
	}
	peer, known := r.Mesh.Peer(mydcp.Identity(caller))
	if !known || !peer.Member {
		return nil, mydcp.ErrAdmission
	}
	read, err := schema.Decode[control.IngressRead](input)
	if err != nil || read.Query.Node != r.Engine().ObservedNodeID() {
		return nil, mydcp.ErrAdmission
	}
	page, err := r.observeIngressOwner(ctx, read)
	if err != nil {
		return nil, err
	}
	return json.Marshal(page)
}
