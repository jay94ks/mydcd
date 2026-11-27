// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
)

type AppOverrideChange struct {
	Target      *[32]byte `json:",omitempty"`
	Tenant, App string
	Path        []string
	Revision    uint64
	Value       json.RawMessage        `json:",omitempty"`
	Refs        []deployment.ObjectRef `json:",omitempty"`
}
type AppCDFieldRequest struct {
	App    string
	Path   []string
	Part   int      `json:",omitempty"`
	Digest [32]byte `json:",omitempty"`
}
type AppCDField struct {
	Target      [32]byte
	Schema      uint8
	Tenant, App string
	Revision    uint64
	Path        []string
	Override    *AppCDFieldOverride             `json:",omitempty"`
	Refs        []deployment.ObjectRef          `json:",omitempty"`
	Values      *deployment.DeliveryFieldValues `json:",omitempty"`
	ValuesPart  *AppCDSnapshotPart              `json:",omitempty"`
}
type AppCDFieldOverride struct {
	Revision uint64
	Actor    string
	Anchors  []deployment.DeliveryOverrideAnchor
}

// AppDeliveryField reads one explicit app field, not a full plan or native
// receipt. Large override maps are never copied into every public app row.
func (p Policy) AppDeliveryField(s state.State, c access.Catalog, actor, tenant string, q AppCDFieldRequest) (AppCDField, error) {
	var out AppCDField
	read := AppCDReadRequest{App: q.App, Part: q.Part, Digest: q.Digest}
	if !read.Valid(false) || !deployment.AllowedAppOverride(q.Path) || c.Authorize(actor, tenant, access.Read, "") != nil {
		return out, access.ErrDenied
	}
	a, err := p.Apps(s)
	if err != nil {
		return out, err
	}
	entry, exists := a.entries[appKey(tenant, q.App)]
	if !exists || entry.Delivery == nil {
		return out, ErrCatalog
	}
	d := *entry.Delivery
	out = AppCDField{Schema: 1, Tenant: tenant, App: q.App, Revision: d.Revision(), Path: slices.Clone(q.Path)}
	for _, o := range d.Overrides() {
		if slices.Equal(o.Path, q.Path) {
			out.Override = &AppCDFieldOverride{o.Revision, o.Actor, o.Anchors}
			break
		}
	}
	b, exists := d.CandidateBlueprint()
	if !exists {
		return out, ErrCatalog
	}
	instances, err := b.ServiceInstances(q.Path[1])
	if err != nil {
		return out, err
	}
	for _, instance := range instances {
		key := deployment.ResourceKey("task", tenant, q.App, instance.ResourceID())
		for _, claim := range entry.Inventory.Claims() {
			current := s.Object(key)
			if claim.Step.Key == key && !claim.Removed && !claim.Retained && current.Present && current.Revision == claim.Result.Revision && current.Generation == claim.Result.Generation && current.Value == claim.Command.Value {
				out.Refs = append(out.Refs, deployment.ObjectRef{Key: key, Revision: current.Revision, Generation: current.Generation})
				break
			}
		}
	}
	slices.SortFunc(out.Refs, func(a, b deployment.ObjectRef) int { return strings.Compare(a.Key, b.Key) })
	out.Target = appFieldTarget(s, a, entry, q.Path)
	values, err := d.FieldValues(q.Path)
	if err != nil {
		return AppCDField{}, err
	}
	part, err := cdSnapshotPart(tenant, q.App, "field-values", read, values)
	if err != nil {
		return AppCDField{}, err
	}
	if part.Length <= deployment.ArtifactPartBytes {
		out.Values = &values
	} else {
		out.ValuesPart = &part
	}
	return out, nil
}

func (p Policy) reduceAppOverride(s state.State, a Apps, op UserOperation) (map[string][]byte, state.Code) {
	var q AppOverrideChange
	if canonical(op.Change.Payload, &q) != nil {
		return nil, state.Invalid
	}
	entry, exists := a.entries[appKey(q.Tenant, q.App)]
	if !exists || entry.Delivery == nil {
		return nil, state.ConditionFailed
	}
	if AppFieldCASAllowed(op.Change) {
		if q.Target == nil || op.Change.Expected == 0 || op.Change.Expected > entry.Delivery.Revision() || *q.Target != appFieldTarget(s, a, entry, q.Path) {
			return nil, state.ConditionFailed
		}
	} else if entry.Delivery.Revision() != op.Change.Expected {
		return nil, state.ConditionFailed
	}
	volumes, err := p.Volumes(s)
	if err != nil || volumes.appMovePending(q.Tenant, q.App) {
		return nil, state.ConditionFailed
	}
	c, err := p.Catalog(s)
	if err != nil {
		return nil, state.Invalid
	}
	d := *entry.Delivery
	scope := entry.Inventory.Scope()
	ctx, err := p.AppPlanning(s, op.Session.User, scope.Tenant)
	if err != nil {
		return nil, state.ConditionFailed
	}
	ctx.Actor, ctx.Project, ctx.Deployment = d.Principal(), scope.App, scope.Deployment
	if begin, e := appOriginBegin(entry.Origin, scope); e == nil {
		ctx.DefaultNode = begin.DefaultNode
	}
	_, active := entry.Inventory.Execution()
	metadataOnly := d.Paused() && !active && entry.Inventory.Quiescent()
	if op.Change.Action == "override-app" {
		if !deployment.AllowedAppOverride(q.Path) || len(q.Value) == 0 || len(q.Refs) == 0 || len(q.Refs) > 128 {
			return nil, state.Invalid
		}
		d, err = d.PutOverride(d.Revision(), q.Revision, c, ctx, op.Session.User, q.Path, q.Value, q.Refs)
	} else {
		if op.Change.Action != "release-app-override" || len(q.Value) != 0 || len(q.Refs) != 0 || q.Revision == 0 {
			return nil, state.Invalid
		}
		// A historical network field can only be returned after the old app
		// has stopped. New app input can never create that ownership again.
		if !deployment.AllowedAppOverride(q.Path) && !metadataOnly {
			return nil, state.ConditionFailed
		}
		for _, old := range d.Overrides() {
			if !slices.Equal(old.Path, q.Path) {
				continue
			}
			action := access.Deploy
			if len(q.Path) > 3 && q.Path[0] == "networks" {
				action = access.ManageNetwork
				if q.Path[3] == "dns" {
					action = access.ManageServices
				}
			}
			for _, anchor := range old.Anchors {
				if metadataOnly {
					err = c.AuthorizeSessionCleanup(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, q.Tenant, action)
				} else {
					err = c.AuthorizeSession(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, q.Tenant, action, anchor.Node)
				}
				if err != nil {
					return nil, state.Forbidden
				}
			}
		}
		d, err = d.ReleaseOverride(d.Revision(), q.Revision, c, ctx, op.Session.User, q.Path)
	}
	if err != nil {
		return nil, state.ConditionFailed
	}
	if !metadataOnly || op.Change.Action == "override-app" {
		b, ok := d.CandidateBlueprint()
		if !ok || p.authorizeCDSelection(s, c, entry, b, &op, entry.Local) != nil {
			return nil, state.Forbidden
		}
	}
	entry.Delivery = &d
	a.entries[appKey(q.Tenant, q.App)] = entry
	return p.appsCheckpoint(s, a, uint64(op.At))
}
