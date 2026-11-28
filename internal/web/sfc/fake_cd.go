// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
)

// CD (UI-40..43) in the fake, with the real payload types and the CAS
// rules of control.Apps: every CD action has Expected = the CD revision
// and, when given, AppCDChange.Target = the execution intent target of the
// apps row; sync/recover choose the row's candidate (Choice.Candidate,
// Choice.Registration); configure-app-cd carries PolicyRevision; override
// actions name the field target of app-cd-field and the override revision
// (0 for a new one). No source fetch or planning is modeled: sync makes
// the candidate the running commit, configure replaces the policy.

type cdOverride struct {
	Path     []string
	Revision uint64
	Actor    string
	Value    json.RawMessage
}

// cdPolicy is the fixture CD row's policy.
func cdPolicy(cd *AppCD) *deployment.DeliveryDeclaration {
	p := &deployment.DeliveryDeclaration{Enabled: true, Poll: 60}
	p.Source.Kind, p.Source.Repository, p.Source.Ref, p.Source.Path = "git", cd.Repository, "refs/heads/"+cd.Branch, "app.yaml"
	p.Sync.Mode, p.Sync.Drift = cd.Mode, "report"
	return p
}

// loadCD fills the stored part of a fixture CD row.
func (w *world) loadCD(a *fakeApp, submitter string) {
	if a.view.CD == nil {
		return
	}
	cd := *a.view.CD
	if cd.PolicyRevision == 0 {
		cd.PolicyRevision = 1
	}
	if cd.Policy == nil {
		cd.Policy = cdPolicy(&cd)
	}
	for id, u := range w.users {
		if u.rec.Username == submitter {
			cd.Principal = id
		}
	}
	a.view.CD = &cd
}

func cdTarget(tenant, app string, rev uint64) [32]byte {
	return fakeDigest("cd-target", tenant, app, hex.EncodeToString([]byte{byte(rev >> 8), byte(rev)}))
}

func cdFieldTarget(tenant, app string, path []string, rev uint64) [32]byte {
	return fakeDigest("cd-field", tenant, app, strings.Join(path, "\x00"), hex.EncodeToString([]byte{byte(rev >> 8), byte(rev)}))
}

// cdView is the read form of a CD row (derived status fields).
func (a *fakeApp) cdView() *AppCD {
	if a.view.CD == nil {
		return nil
	}
	cd := *a.view.CD
	t, app := a.view.Tenant, a.view.App
	if cd.Candidate != "" {
		cd.CandidateDigest = candidateDigest(t, app, cd.Candidate)
	}
	cd.Target, cd.Registration = cdTarget(t, app, cd.Revision), fakeDigest("cd-registration", t, app)
	cd.Approvers = slices.Clone(cd.Approvers)
	cd.LocalServices, cd.LocalRevision, cd.LocalActor = nil, 0, ""
	if a.cd != nil {
		cd.LocalRevision, cd.LocalActor = a.cd.localRev, a.cd.localBy
		if a.cd.local != "" {
			cd.LocalServices = serviceNames(a.cd.local)
		}
	}
	cd.LocalTarget = fakeDigest("cd-local-target", t, app, cd.Running)
	cd.Source, cd.Sync, cd.EffectiveSync, cd.Operation, cd.Health = "Ready", "InSync", "InSync", "Succeeded", "Healthy"
	if cd.SourceError != "" {
		cd.Source = "Error"
	}
	if cd.Candidate != "" && cd.Candidate != cd.Running {
		cd.Sync, cd.Operation, cd.ChangeCount = "OutOfSync", "Planned", a.cdChanges().Count
		cd.EffectiveSync = cd.Sync
	}
	if cd.Paused {
		cd.EffectiveSync = "Paused"
	}
	cd.LastSuccessCommit = cd.Running
	cd.OverridePaths, cd.OverrideCount = nil, len(a.cdOverrides)
	for _, o := range a.cdOverrides {
		cd.OverridePaths = append(cd.OverridePaths, slices.Clone(o.Path))
	}
	return &cd
}

func (c *fakeConn) AppDeliveryField(ctx context.Context, tenant string, q control.AppCDFieldRequest) (AppCDField, error) {
	const m = "app-cd-field"
	if err := c.appRead(ctx, m, tenant); err != nil {
		return AppCDField{}, err
	}
	defer c.unlock()
	if !deployment.AllowedAppOverride(q.Path) {
		return AppCDField{}, fail(m, CodeDenied, "")
	}
	a := c.f.w.apps[tenant+"/"+q.App]
	if a == nil || a.view.CD == nil {
		return AppCDField{}, fail(m, CodeInvalid, "not a CD app")
	}
	out := AppCDField{Schema: 1, Tenant: tenant, App: q.App, Revision: a.view.CD.Revision, Path: slices.Clone(q.Path),
		Target: cdFieldTarget(tenant, q.App, q.Path, a.view.CD.Revision)}
	for _, o := range a.cdOverrides {
		if slices.Equal(o.Path, q.Path) {
			out.Override = &control.AppCDFieldOverride{Revision: o.Revision, Actor: o.Actor}
		}
	}
	for _, t := range a.tasks {
		if t.Service == q.Path[1] {
			out.Refs = []deployment.ObjectRef{{Key: deployment.ResourceKey("task", tenant, q.App, t.Service), Revision: t.Generation, Generation: 1}}
			break
		}
	}
	return out, nil
}

func (c *fakeConn) applyCD(op UserOperation, actor string, next uint64) error {
	w := c.f.w
	ch := op.Change
	if ch.Action == ActionOverrideApp || ch.Action == ActionReleaseOverride {
		return c.applyCDOverride(op, actor, next)
	}
	var q control.AppCDChange
	if decodePayload(ch.Payload, &q) != nil || q.Tenant == "" || q.App == "" {
		return errors.New("payload")
	}
	if !w.canManage(actor, q.Tenant) {
		return errForbidden
	}
	a := w.apps[q.Tenant+"/"+q.App]
	if a != nil && a.view.CD == nil && ch.Action == ActionConfigureAppCD {
		return c.attachCD(a, q, ch.Expected, next)
	}
	if a == nil || a.view.CD == nil {
		return errCAS
	}
	cur := a.cdView()
	if ch.Expected != cur.Revision || q.Target != nil && *q.Target != cur.Target {
		return errCAS
	}
	cd := a.view.CD
	switch ch.Action {
	case ActionSyncApp, ActionRecoverApp:
		if q.Choice == nil || q.Choice.Operation == "" || cur.Candidate == "" || q.Choice.Candidate != cur.CandidateDigest || q.Choice.Registration != cur.Registration {
			return errCAS
		}
		if cd.Paused && ch.Action == ActionSyncApp {
			return errCAS
		}
		if err := c.cdRun(a, cd.Candidate, q.Choice.Operation, actor, c.f.now().Unix()); err != nil {
			return err
		}
	case ActionReplanApp:
		// a person's replan brings back a rejected head commit.
		if s := a.cd; s != nil && s.rejected[s.head] {
			delete(s.rejected, s.head)
			cd.Candidate = s.head
			w.cdCandidate(a, s.head, c.f.now().Unix())
		}
	case ActionAbandonAppSync:
	case ActionPauseAppCD, ActionResumeAppCD:
		if cd.Paused == (ch.Action == ActionPauseAppCD) {
			return errCAS
		}
		cd.Paused = ch.Action == ActionPauseAppCD
		kind := EventCDResumed
		if cd.Paused {
			kind = EventCDPaused
		}
		w.cdEvent(a, kind, cd.Running, actor, "", "", c.f.now().Unix())
	case ActionConfigureAppCD:
		if q.Policy == nil || q.PolicyRevision != cd.PolicyRevision || q.Policy.Source.Repository == "" || !slices.Contains([]string{"automatic", "manual"}, q.Policy.Sync.Mode) {
			return errors.New("payload")
		}
		p := *q.Policy
		cd.Policy, cd.PolicyRevision = &p, cd.PolicyRevision+1
		cd.Repository, cd.Branch, cd.Mode = p.Source.Repository, strings.TrimPrefix(p.Source.Ref, "refs/heads/"), p.Sync.Mode
	default:
		return errors.New("action")
	}
	cd.Revision = next
	return nil
}

// attachCD is the first policy of an app deployed without CD, as sfcd's
// attachUserCD: policy revision 0, no target, CAS = the app's revision; the
// app's current execution becomes the running candidate.
func (c *fakeConn) attachCD(a *fakeApp, q control.AppCDChange, expected, next uint64) error {
	if q.Choice != nil || q.PolicyRevision != 0 || q.Target != nil || expected != a.view.Revision {
		return errCAS
	}
	if q.Policy == nil || q.Policy.Source.Repository == "" || !slices.Contains([]string{"automatic", "manual"}, q.Policy.Sync.Mode) {
		return errors.New("payload")
	}
	p := *q.Policy
	a.view.CD = &AppCD{Revision: next, Policy: &p, PolicyRevision: 1, Repository: p.Source.Repository,
		Branch: strings.TrimPrefix(p.Source.Ref, "refs/heads/"), Mode: p.Sync.Mode}
	a.view.Revision = next
	return nil
}

func (c *fakeConn) applyCDOverride(op UserOperation, actor string, next uint64) error {
	w := c.f.w
	ch := op.Change
	var q control.AppOverrideChange
	if decodePayload(ch.Payload, &q) != nil || !deployment.AllowedAppOverride(q.Path) {
		return errors.New("payload")
	}
	if !w.canManage(actor, q.Tenant) {
		return errForbidden
	}
	a := w.apps[q.Tenant+"/"+q.App]
	if a == nil || a.view.CD == nil {
		return errCAS
	}
	cd := a.view.CD
	if ch.Expected != cd.Revision || q.Target == nil || *q.Target != cdFieldTarget(q.Tenant, q.App, q.Path, cd.Revision) {
		return errCAS
	}
	i := slices.IndexFunc(a.cdOverrides, func(o cdOverride) bool { return slices.Equal(o.Path, q.Path) })
	have := uint64(0)
	if i >= 0 {
		have = a.cdOverrides[i].Revision
	}
	if q.Revision != have {
		return errCAS
	}
	if ch.Action == ActionOverrideApp {
		if len(q.Value) == 0 || len(q.Refs) != 1 {
			return errors.New("payload")
		}
		o := cdOverride{Path: slices.Clone(q.Path), Revision: next, Actor: actor, Value: append(json.RawMessage(nil), q.Value...)}
		if i >= 0 {
			a.cdOverrides[i] = o
		} else {
			a.cdOverrides = append(a.cdOverrides, o)
		}
	} else {
		if i < 0 || len(q.Value) != 0 || len(q.Refs) != 0 {
			return errCAS
		}
		a.cdOverrides = slices.Delete(a.cdOverrides, i, i+1)
	}
	cd.OverrideRevision, cd.Revision = next, next
	return nil
}
