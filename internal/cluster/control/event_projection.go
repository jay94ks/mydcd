// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/eventlog"
)

// ProjectEvents uses only committed inputs and immutable before/after state.
// It never reads wall time or produces a replacement management decision.
func (p Policy) ProjectEvents(before, after state.State, command state.Command, result state.Result) ([]eventlog.Event, error) {
	shellEvents, shellErr := p.NodeShellEvents(before, after, command, result)
	if shellErr != nil {
		return nil, shellErr
	}
	if result.Code != state.Applied || result.Index != after.Index() {
		return shellEvents, nil
	}
	var header struct {
		At                             uint64
		Tenant, App, Operation, Action string
	}
	var origin *UserOperation
	if strings.HasPrefix(command.Actor, "user/") {
		var op UserOperation
		if canonical([]byte(command.Value), &op) != nil || op.At <= 0 {
			return nil, nil
		}
		origin = &op
		header.At = uint64(op.At)
		header.Action = op.Change.Action
	} else if command.Kind == state.ModuleReport {
		if json.Unmarshal([]byte(command.Value), &header) != nil {
			return nil, nil
		}
	} else {
		return nil, nil
	}
	if header.At == 0 || header.At > ^uint64(0)/1000 {
		return nil, nil
	}
	at := header.At * 1000
	base := eventlog.Detail{Operation: header.Operation}
	if origin != nil {
		eventReason(&base, *origin)
		base.Operation = origin.RequestID
	}
	events := shellEvents
	emit := func(kind, scope string, target eventlog.Target, detail eventlog.Detail) {
		events = append(events, eventlog.Event{Kind: kind, Scope: scope, At: at, Target: target, Detail: detail})
	}
	if command.Key == IngressManagementKey && origin != nil && (header.Action == "ingress-block" || header.Action == "ingress-unblock" || header.Action == "ingress-block-extend") {
		book, err := p.IngressManagement(after)
		if err != nil {
			return nil, err
		}
		for _, record := range book.Blocks {
			if record.Last.RequestID == origin.RequestID {
				kind := "ingress-blocked"
				if record.Removed {
					kind = "ingress-unblocked"
				}
				scope := "app"
				if record.Block.App == "" {
					scope = "tenant"
				}
				if record.Block.Tenant == "" {
					scope = "cluster"
				}
				emit(kind, scope, eventlog.Target{Tenant: record.Block.Tenant, App: record.Block.App, Node: record.Block.Node, Gateway: record.Block.Gateway, RouteID: record.Block.Route, Host: record.Block.Host, Prefix: record.Block.Prefix}, base)
			}
		}
	}
	if command.Key == AppsKey && before.Object(AppsKey) != after.Object(AppsKey) {
		old, err := p.readOnlyApps(before)
		if err != nil {
			return nil, err
		}
		next, err := p.readOnlyApps(after)
		if err != nil {
			return nil, err
		}
		keys := []string{}
		for key := range next.entries {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		for _, key := range keys {
			n := next.entries[key]
			o := old.entries[key]
			if origin != nil && header.Action == "standalone-extend" && n.Standalone != nil && n.Standalone.LastExtension != nil && n.Standalone.LastExtension.RequestID == origin.RequestID {
				scope := n.Inventory.Scope()
				detail := base
				detail.Value = uint64(n.Standalone.ExpiresAt)
				emit("standalone-extended", "app", eventlog.Target{Tenant: scope.Tenant, App: scope.App, Deployment: scope.Deployment, Node: n.Standalone.Node}, detail)
			}
			if origin != nil && header.Action == "restart-task" {
				for _, restart := range n.TaskRestarts {
					if restart.Origin.RequestID != origin.RequestID {
						continue
					}
					t := restart.Plan.Container
					d := base
					emit("task-restart-requested", "app", eventlog.Target{Tenant: t.Tenant, App: t.App, Service: t.Service, Task: t.Instance, Native: t.NativeID, Node: t.Node, Generation: t.Generation, Revision: t.Revision}, d)
				}
			}
			if n.Delivery == nil {
				continue
			}
			scope := n.Inventory.Scope()
			if header.Tenant != "" && scope.Tenant != header.Tenant || header.App != "" && scope.App != header.App {
				continue
			}
			// Unchanged app entries need neither repeated status work nor events.
			if n.Delivery.Revision() == deliveryRevision(o.Delivery) && n.Inventory.Revision() == o.Inventory.Revision() {
				continue
			}
			target := eventlog.Target{Tenant: scope.Tenant, App: scope.App, Deployment: scope.Deployment}
			detail := base
			detail.FromVersion = o.LastVersion
			selection, hasCandidate := n.Delivery.CandidateSelection()
			if hasCandidate {
				detail.CandidateID = hex.EncodeToString(selection.Candidate[:])
				detail.Commit = selection.Commit
			}
			oldSelection, hadCandidate := deliveryCandidate(o.Delivery)
			changedCandidate := hasCandidate && (!hadCandidate || selection.Candidate != oldSelection.Candidate)
			if changedCandidate {
				emit("cd-candidate-created", "app", target, detail)
				users, userErr := p.Catalog(after)
				if userErr != nil {
					return nil, userErr
				}
				if n.Delivery.Policy().Sync.Mode != "automatic" && !n.Delivery.Rejected() && !n.Delivery.ExplicitApprovalReady(users) {
					emit("cd-approval-required", "app", target, detail)
				}
			}
			if origin != nil && (header.Action == "cd-approve" || header.Action == "cd-reject") && n.CDDecision != nil && n.CDDecision.Origin.RequestID == origin.RequestID {
				decision := detail
				decision.CandidateID = hex.EncodeToString(n.CDDecision.Selection.Candidate[:])
				decision.Commit = n.CDDecision.Selection.Commit
				kind := "cd-approved"
				if header.Action == "cd-reject" {
					kind = "cd-rejected"
				}
				emit(kind, "app", target, decision)
			}
			if o.Delivery != nil && o.Delivery.Paused() != n.Delivery.Paused() {
				kind := "cd-resumed"
				if n.Delivery.Paused() {
					kind = "cd-paused"
				}
				emit(kind, "app", target, detail)
			}
			newView := appView(n, scope)
			oldView := AppView{}
			if o.Delivery != nil {
				oldView = appView(o, o.Inventory.Scope())
			}
			current, previous := newView.Operation, oldView.Operation
			if running, ok := n.Delivery.Selection(); ok {
				detail.CandidateID = hex.EncodeToString(running.Candidate[:])
				detail.Commit = running.Commit
			}
			detail.Operation = current.ID
			for _, version := range n.Versions {
				if version.Operation == current.ID {
					detail.ToVersion = version.Revision
					detail.FromVersion = 0
					for _, past := range n.Versions {
						if past.Revision < version.Revision && past.Revision > detail.FromVersion {
							detail.FromVersion = past.Revision
						}
					}
					break
				}
			}
			if current.ID != "" && current.ID != previous.ID {
				emit("cd-sync-started", "app", target, detail)
			}
			if current.ID != "" && (current.ID != previous.ID || current.Status != previous.Status || current.Failed != previous.Failed) {
				if current.Status == "Succeeded" {
					emit("cd-sync-succeeded", "app", target, detail)
					if priorAppInput(n, current.ID) {
						emit("cd-rolled-back", "app", target, detail)
					}
				} else if current.Status == "Failed" || current.Failed {
					d := detail
					d.Code = "CD_EXECUTION_FAILED"
					emit("cd-sync-failed", "app", target, d)
				}
			}
			users, err := p.Catalog(after)
			if err != nil {
				return nil, err
			}
			p.ObserveAppCD(after, next, users, &newView, header.At)
			oldUsers, err := p.Catalog(before)
			if err != nil {
				return nil, err
			}
			if o.Delivery != nil {
				p.ObserveAppCD(before, old, oldUsers, &oldView, header.At)
			}
			if newView.CD != nil && newView.CD.Status != nil && newView.CD.Status.Sync == "OutOfSync" && (oldView.CD == nil || oldView.CD.Status == nil || oldView.CD.Status.Sync != "OutOfSync") {
				d := detail
				d.Code = "CD_DESIRED_DIFFERS"
				emit("cd-drift-detected", "app", target, d)
			}
		}
	}
	if command.Key == MembersKey && origin != nil && (header.Action == "cordon-node" || header.Action == "uncordon-node") {
		target, err := cordonTarget(header.Action, origin.Change.Payload)
		if err != nil {
			return nil, ErrCatalog
		}
		kind := "node-cordoned"
		if header.Action == "uncordon-node" {
			kind = "node-uncordoned"
		}
		emit(kind, "node", eventlog.Target{Node: target.ID}, base)
	}
	if command.Key == CompactKey && before.Object(CompactKey) != after.Object(CompactKey) {
		old, err := p.Compactions(before)
		if err != nil {
			return nil, err
		}
		next, err := p.Compactions(after)
		if err != nil {
			return nil, err
		}
		for _, job := range next.Records {
			previous, _ := old.Record(job.Job.Operation)
			for _, node := range job.Job.Nodes {
				was, known := previous.Job.Node(node.Node)
				if known && was.State == node.State {
					continue
				}
				kind := ""
				if node.State == "running" {
					kind = "raft-compact-started"
				} else if node.State == "done" || node.State == "failed" || node.State == "skipped" {
					kind = "raft-compact-completed"
				}
				if kind != "" {
					d := eventlog.Detail{Operation: job.Job.Operation, State: node.State, Code: node.Code}
					eventReason(&d, job.Origin)
					emit(kind, "cluster", eventlog.Target{Node: node.Node}, d)
				}
			}
		}
	}
	if command.Key == ImageCacheKey && before.Object(ImageCacheKey) != after.Object(ImageCacheKey) {
		old, err := p.ImageCacheJobs(before)
		if err != nil {
			return nil, err
		}
		next, err := p.ImageCacheJobs(after)
		if err != nil {
			return nil, err
		}
		for _, job := range next.Records {
			previous, _ := old.Record(job.Operation)
			for _, part := range job.Parts {
				existed := false
				for _, p := range previous.Parts {
					if p.ID == part.ID {
						existed = true
						break
					}
				}
				if existed {
					continue
				}
				d := eventlog.Detail{Operation: job.Operation, State: part.State, Code: part.Code}
				eventReason(&d, job.Origin)
				emit("node-cache-cleaned", "cluster", eventlog.Target{Node: job.Plan.Node, Native: part.ID}, d)
			}
		}
	}

	if command.Key == TunnelReconnectKey && before.Object(TunnelReconnectKey) != after.Object(TunnelReconnectKey) {
		old, err := p.TunnelReconnections(before)
		if err != nil {
			return nil, err
		}
		next, err := p.TunnelReconnections(after)
		if err != nil {
			return nil, err
		}
		for _, row := range next.Records {
			previous, _ := old.Record(row.Operation)
			if row.Result == nil || previous.Result != nil {
				continue
			}
			kind := "tunnel-reconnected"
			if row.Result.State == "failed" {
				kind = "tunnel-down"
			}
			d := eventlog.Detail{Operation: row.Operation, State: row.Result.State, Code: row.Result.Code}
			eventReason(&d, row.Origin)
			emit(kind, "node", eventlog.Target{Node: row.Plan.Node, PairID: row.Plan.PairID}, d)
		}
	}
	if command.Key == RegistriesKey && before.Object(RegistriesKey) != after.Object(RegistriesKey) {
		old, err := p.Registries(before)
		if err != nil {
			return nil, err
		}
		next, err := p.Registries(after)
		if err != nil {
			return nil, err
		}
		keys := []string{}
		for key := range next.entries {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		for _, key := range keys {
			n := next.entries[key]
			o := old.entries[key]
			was := o.Active != nil && o.Active.Ready != nil
			stopped := n.Active == nil && o.Active != nil || n.Active != nil && n.Active.Ready == nil
			if was && stopped {
				d := base
				d.Resource = n.Spec.ID
				d.State = "stopped"
				emit("registry-stopped", "tenant", eventlog.Target{Tenant: n.Spec.Tenant, Node: n.Spec.Node}, d)
			}
		}
	}

	for _, e := range events {
		if !e.Valid() {
			return nil, eventlog.ErrInvalid
		}
	}
	return events, nil
}
func eventReason(detail *eventlog.Detail, op UserOperation) {
	detail.Actor = op.Session.User
	if op.Reason != nil {
		detail.Reason = op.Reason.Text
		detail.IncidentID = op.Reason.IncidentID
		detail.ApprovedBy = op.Reason.ApprovedBy
	}
}
func deliveryRevision(d *deployment.Delivery) uint64 {
	if d == nil {
		return 0
	}
	return d.Revision()
}
func deliveryCandidate(d *deployment.Delivery) (deployment.DeliverySelection, bool) {
	if d == nil {
		return deployment.DeliverySelection{}, false
	}
	return d.CandidateSelection()
}
func priorAppInput(entry appEntry, operation string) bool {
	var current *appVersion
	for i := range entry.Versions {
		if entry.Versions[i].Operation == operation {
			current = &entry.Versions[i]
			break
		}
	}
	if current == nil {
		return false
	}
	var immediatelyPrevious *appVersion
	for i := range entry.Versions {
		past := &entry.Versions[i]
		if past.Revision < current.Revision && (immediatelyPrevious == nil || past.Revision > immediatelyPrevious.Revision) {
			immediatelyPrevious = past
		}
	}
	if immediatelyPrevious == nil || immediatelyPrevious.Digest == current.Digest {
		return false
	}
	for _, past := range entry.Versions {
		if past.Revision < current.Revision && past.Digest == current.Digest && past.Status == "Succeeded" {
			return true
		}
	}
	return false
}

// EventAccess is evaluated on the current management view before any local
// cursor, filtering, page limit or source metadata is revealed.
func (p Policy) EventAccess(s state.State, session access.Session, at int64, q eventlog.Query) (func(eventlog.Record) bool, error) {
	p, err := p.Current(s)
	if err != nil || !q.Valid() {
		return nil, access.ErrDenied
	}
	users, err := p.Catalog(s)
	if err != nil {
		return nil, err
	}
	action := access.Read
	if q.Tenant == "" {
		action = access.ManageCluster
	}
	if users.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, q.Tenant, action, "") != nil {
		return nil, access.ErrDenied
	}
	var nodes []string
	if q.Tenant != "" {
		tenant, known := users.Tenant(q.Tenant)
		if !known {
			return nil, access.ErrDenied
		}
		nodes = tenant.AllowedNodes
		if q.Node != "" && !slices.Contains(nodes, q.Node) {
			return nil, access.ErrDenied
		}
	}
	members, err := p.Members(s)
	if err != nil {
		return nil, err
	}
	return func(record eventlog.Record) bool {
		if !record.Valid() || record.Cluster != p.Cluster || !members.HistoricalMemberKey(record.SourceKey) {
			return false
		}
		if q.Tenant == "" {
			return true
		}
		if record.Event.Target.Tenant != q.Tenant {
			return false
		}
		if node := record.Event.Target.Node; node != "" {
			return slices.Contains(nodes, node)
		}
		// Committed app/CD events can be projected by a control which does
		// not host this tenant's containers. Its source is a journal location,
		// not an extra tenant node/resource permission.
		return record.Event.Authority != "" || slices.Contains(nodes, record.SourceNode)
	}, nil
}
