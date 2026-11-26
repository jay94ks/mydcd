// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/userauth"
)

// This file holds the real adapter's page reads whose web type is now the
// product type (R04 step 2): the server shapes them for the screen.

func (c *realConn) Lifecycles(ctx context.Context, tenant, after string) (Page[LifecycleEntry], error) {
	reply, err := realCall(ctx, c, "lifecycles", func(u userauth.Client, s access.Session) (userauth.Reply, error) {
		return u.LifecyclePage(ctx, c.peer, s, tenant, after)
	})
	if err != nil {
		return Page[LifecycleEntry]{}, err
	}
	return Page[LifecycleEntry]{Items: reply.Lifecycles, Next: reply.LifecyclesNext, Revision: reply.LifecycleRootRevision}, nil
}

func (c *realConn) AppUploads(ctx context.Context, tenant, after string) (Page[AppUploadView], error) {
	reply, err := realCall(ctx, c, "app-uploads", func(u userauth.Client, s access.Session) (userauth.Reply, error) {
		return u.AppUploadPage(ctx, c.peer, s, tenant, after)
	})
	if err != nil {
		return Page[AppUploadView]{}, err
	}
	return Page[AppUploadView]{Items: reply.Uploads, Next: reply.UploadsNext, Revision: reply.AppsRootRevision}, nil
}

func (c *realConn) Apps(ctx context.Context, tenant, after string) (Page[AppView], error) {
	reply, err := realCall(ctx, c, "apps", func(u userauth.Client, s access.Session) (userauth.Reply, error) {
		return u.AppPage(ctx, c.peer, s, tenant, after)
	})
	if err != nil {
		return Page[AppView]{}, err
	}
	items := make([]AppView, 0, len(reply.Apps))
	for _, a := range reply.Apps {
		items = append(items, appView(a))
	}
	return Page[AppView]{Items: items, Next: reply.AppsNext, Revision: reply.AppsRootRevision}, nil
}

// appView is the screen form of an apps row: the CD view is flattened to
// the source, sync mode and commits the screen shows.
func appView(a control.AppView) AppView {
	v := AppView{Tenant: a.Tenant, App: a.App, Deployment: a.Deployment, Revision: a.Revision, Operation: a.Operation,
		Claims: a.Claims, Health: a.Health, ObservedAt: a.ObservedAt, Retiring: a.Retirement != nil}
	if a.CD != nil {
		v.CD = appCD(*a.CD)
	}
	return v
}

func appCD(d control.AppCDView) *AppCD {
	policy := d.Policy
	cd := &AppCD{Revision: d.Revision, Repository: policy.Source.Repository, Branch: policy.Source.Ref, Mode: policy.Sync.Mode,
		Paused: d.Paused, SourceError: d.SourceError, PolicyRevision: d.PolicyRevision, OverrideRevision: d.OverrideRevision,
		Principal: d.Principal, Policy: &policy, Blocked: d.Blocked, ChangeCount: d.ChangeCount, OverrideCount: d.OverrideCount,
		Target: d.Target, Registration: d.Registration, Approvers: d.Approvers,
		LocalServices: d.LocalServices, LocalRevision: d.LocalRevision, LocalActor: d.LocalActor, LocalTarget: d.LocalTarget}
	if d.Running != nil {
		cd.Running = d.Running.Commit
	}
	if d.Candidate != nil {
		cd.Candidate, cd.CandidateDigest = d.Candidate.Commit, d.Candidate.Candidate
	}
	if s := d.Status; s != nil {
		cd.Sync, cd.EffectiveSync, cd.Operation, cd.Health, cd.Source = s.Sync, s.EffectiveSync, s.Operation, s.Health, s.Source
		cd.Transition, cd.TransitionPhase = s.Transition, s.TransitionPhase
		cd.LastSuccessCommit, cd.ActiveOperation, cd.OverridePaths = s.LastSuccessCommit, s.ActiveOperation, s.OverridePaths
		if cd.SourceError == "" {
			cd.SourceError = s.SourceError
		}
	}
	return cd
}

func (c *realConn) AppOperation(ctx context.Context, tenant, app, id string) (AppOperation, error) {
	return c.appOperation(ctx, "app-operation", tenant, control.AppOperationRequest{App: app, ID: id})
}

func (c *realConn) StandaloneOperation(ctx context.Context, tenant, name, id string) (AppOperation, error) {
	return c.appOperation(ctx, "app-operation", tenant, control.AppOperationRequest{Standalone: name, ID: id})
}

// appOperation is an exact operation result. Steps are the steps a
// current deploy still waits on; mydcd keeps no start time.
func (c *realConn) appOperation(ctx context.Context, m, tenant string, q control.AppOperationRequest) (AppOperation, error) {
	reply, err := realCall(ctx, c, m, func(u userauth.Client, s access.Session) (userauth.Reply, error) {
		return u.AppOperation(ctx, c.peer, s, tenant, q)
	})
	if err != nil {
		return AppOperation{}, err
	}
	v := reply.AppOperation
	if v == nil || !v.Found || v.Operation == nil {
		return AppOperation{}, fail(m, CodeMissing, "")
	}
	app := v.App
	if v.Standalone != "" {
		app = v.Standalone
	}
	return AppOperation{Tenant: v.Tenant, App: app, ID: v.ID, Status: v.Operation.Status, Failed: v.Operation.Failed,
		Submitter: v.Operation.Submitter, CompletedAt: int64(v.Operation.CompletedAt), Steps: append([]string{}, v.Waiting...)}, nil
}

func (c *realConn) AppSource(ctx context.Context, tenant, app string, version uint64) (AppSource, error) {
	const m = "app-source"
	type source struct {
		raw []byte
		v   control.AppRevisionView
	}
	got, err := realCall(ctx, c, m, func(u userauth.Client, s access.Session) (source, error) {
		raw, v, err := u.ReadAppSource(ctx, c.peer, s, tenant, control.AppSourceSelection{App: app, Revision: version})
		return source{raw, v}, err
	})
	if err != nil {
		return AppSource{}, err
	}
	r := appRevision(got.v)
	return AppSource{Tenant: got.v.Tenant, App: got.v.App, Version: r.Version, Document: got.raw, Digest: r.Digest, Submitter: r.Submitter,
		Operation: r.Operation, AcceptedAt: r.AcceptedAt, Kind: r.Kind}, nil
}

func (c *realConn) AppRevisions(ctx context.Context, tenant, app, after string) (Page[AppRevision], error) {
	reply, err := realCall(ctx, c, "app-revisions", func(u userauth.Client, s access.Session) (userauth.Reply, error) {
		return u.AppRevisions(ctx, c.peer, s, tenant, control.AppSourceSelection{App: app}, after)
	})
	if err != nil {
		return Page[AppRevision]{}, err
	}
	items := make([]AppRevision, 0, len(reply.AppRevisions))
	for _, v := range reply.AppRevisions {
		items = append(items, appRevision(v))
	}
	return Page[AppRevision]{Items: items, Next: reply.AppRevisionsNext, Revision: reply.AppRevisionsRootRevision}, nil
}

// appRevision: Kind "cd" for a CD sync, "web-local" for a change of local
// services over a CD app, "" for a user's up.
func appRevision(v control.AppRevisionView) AppRevision {
	r := AppRevision{Version: v.Revision, Digest: v.Digest, Submitter: v.SubmittedBy, Operation: v.Operation, Status: v.Status,
		AcceptedAt: int64(v.AcceptedAt)}
	switch {
	case v.Automatic:
		r.Kind = "cd"
	case v.LocalRevision != 0:
		r.Kind = "web-local"
	}
	return r
}

func (c *realConn) Standalones(ctx context.Context, tenant, after string) (Page[StandaloneView], error) {
	reply, err := realCall(ctx, c, "standalone-list", func(u userauth.Client, s access.Session) (userauth.Reply, error) {
		return u.StandalonePage(ctx, c.peer, s, tenant, "", after)
	})
	if err != nil {
		return Page[StandaloneView]{}, err
	}
	items := make([]StandaloneView, 0, len(reply.Standalones))
	for _, v := range reply.Standalones {
		items = append(items, StandaloneViewOf(tenant, v, nil))
	}
	return Page[StandaloneView]{Items: items, Next: reply.StandaloneNext, Revision: reply.AppsRootRevision}, nil
}

// Standalone is one row with its stored definition (app-source of the
// standalone's current revision).
func (c *realConn) Standalone(ctx context.Context, tenant, name string) (StandaloneView, error) {
	const m = "standalone-get"
	reply, err := realCall(ctx, c, m, func(u userauth.Client, s access.Session) (userauth.Reply, error) {
		return u.StandalonePage(ctx, c.peer, s, tenant, name, "")
	})
	if err != nil {
		return StandaloneView{}, err
	}
	if len(reply.Standalones) != 1 || reply.Standalones[0].Metadata.Name != name {
		return StandaloneView{}, fail(m, CodeMissing, "")
	}
	v := reply.Standalones[0]
	doc, err := realCall(ctx, c, m, func(u userauth.Client, s access.Session) ([]byte, error) {
		raw, _, err := u.ReadAppSource(ctx, c.peer, s, tenant, control.AppSourceSelection{Standalone: name})
		return raw, err
	})
	if err != nil {
		return StandaloneView{}, err
	}
	return StandaloneViewOf(tenant, v, doc), nil
}

func (c *realConn) Tasks(ctx context.Context, f TaskFilter, after string) (Page[Task], error) {
	reply, err := realCall(ctx, c, "tasks", func(u userauth.Client, s access.Session) (userauth.Reply, error) {
		return u.TasksPage(ctx, c.peer, s, control.TaskSelection{Node: f.Node, Tenant: f.Tenant, App: f.App}, after)
	})
	if err != nil {
		return Page[Task]{}, err
	}
	items := make([]Task, 0, len(reply.Tasks))
	for _, t := range reply.Tasks {
		items = append(items, taskView(t))
	}
	return Page[Task]{Items: items, Next: reply.TasksNext, Revision: reply.TasksRootRevision}, nil
}

// taskView: Instance is the task key container-observe selects; Health is
// the last check (pass is healthy, anything else unhealthy; "none" without
// one).
func taskView(t control.TaskView) Task {
	app := t.App
	if t.Standalone != "" {
		app = t.Standalone
	}
	v := Task{Tenant: t.Tenant, App: app, Service: t.Service, Instance: t.TaskID, Node: t.Node, Image: t.Image, Generation: t.Generation,
		Desired: t.Desired, Observed: t.Observed, Health: "none", ObservedAt: int64(t.ObservedAt)}
	if t.RestartCount != nil {
		v.Restarts = int(*t.RestartCount)
	}
	if t.ExitCode != nil {
		v.ExitCode = int(*t.ExitCode)
	}
	if at, err := time.Parse(time.RFC3339Nano, t.StartedAt); err == nil {
		v.StartedAt = at.Unix()
	}
	if c := t.LastCheck; c != nil {
		v.Health, v.LastCheck = "unhealthy", c.Checker+" "+c.Status
		if c.Status == "pass" {
			v.Health = "healthy"
		}
	}
	return v
}

// AppLogClearPlan: a container whose log driver keeps no local file answers
// Code "unsupported-log-driver" (mydcd does not say which driver).
func (c *realConn) AppLogClearPlan(ctx context.Context, tenant string, sel ContainerSelection) (LogClearPlan, error) {
	const m = "app-log-clear-plan"
	reply, err := realCall(ctx, c, m, func(u userauth.Client, s access.Session) (userauth.Reply, error) {
		return u.QueryLogClear(ctx, c.peer, s, tenant, true, control.AppLogClearQuery{Selection: sel.Ops()})
	})
	var e *Error
	if errors.As(err, &e) && e.Code == "unsupported-log-driver" {
		return LogClearPlan{Code: string(e.Code)}, nil
	}
	if err != nil {
		return LogClearPlan{}, err
	}
	return LogClearPlan{Code: "ok", Plan: reply.LogClearPlan}, nil
}

// AppPlan streams the document to mydcd's planner, as `mydc compose up`
// does. Data is the planned artifact to upload (the blueprint), the diff,
// or the whole move plan; Services is a summary read from the blueprint's
// declared input. A standalone plan is the same blueprint under its internal
// scope (App); mydcd sends no Changes/Impact/Limits summary, so
// AppPlan.Standalone stays nil.
func (c *realConn) AppPlan(ctx context.Context, req AppPlanRequest) (AppPlan, error) {
	const m = "app-plan-stream"
	q := control.AppPlanRequest{Document: req.Document, Project: req.Project, Deployment: req.Deployment, Node: req.Node, Diff: req.Diff, Move: req.Move, Standalone: req.Standalone}
	raw, err := realCall(ctx, c, m, func(u userauth.Client, s access.Session) ([]byte, error) {
		return u.StreamAppPlan(ctx, c.peer, s, req.Tenant, q)
	})
	if err != nil {
		return AppPlan{}, err
	}
	out := AppPlan{Digest: sha256.Sum256(raw), Length: len(raw), Data: raw}
	switch {
	case req.Move != nil:
		p, err := control.DecodeAppMovePlan(raw)
		if err != nil {
			return AppPlan{}, fail(m, CodeUnknown, "malformed move plan")
		}
		out.Move, out.App = &p, p.Begin.Scope.App
	case req.Diff:
		d, err := control.DecodeAppDiff(raw)
		if err != nil || d.Tenant != req.Tenant {
			return AppPlan{}, fail(m, CodeUnknown, "malformed diff")
		}
		out.App = d.App
		var b strings.Builder
		for _, ch := range d.Changes {
			b.WriteString(ch.Action + " " + ch.Key)
			if ch.Reason != "" {
				b.WriteString(" (" + ch.Reason + ")")
			}
			b.WriteByte('\n')
		}
		out.Diff = b.String()
	default:
		b, err := deployment.DecodeBlueprint(raw)
		if err != nil || req.Standalone != nil && b.CheckStandaloneInput() != nil {
			return AppPlan{}, fail(m, CodeUnknown, "malformed plan")
		}
		var bp struct {
			App   string
			Input deployment.Compose
		}
		if json.Unmarshal(raw, &bp) != nil {
			return AppPlan{}, fail(m, CodeUnknown, "malformed plan")
		}
		out.App = bp.App
		for _, name := range slices.Sorted(maps.Keys(bp.Input.Services)) {
			s := bp.Input.Services[name]
			ps := PlannedService{Name: name, Image: s.Image, Node: s.MyDC.Node, Change: "update"}
			if len(s.MyDC.Nodes) > 1 {
				ps.Nodes = slices.Clone(s.MyDC.Nodes)
			}
			for _, e := range s.MyDC.SecretEnv {
				ps.SecretEnv = append(ps.SecretEnv, e.Name)
			}
			out.Services = append(out.Services, ps)
		}
	}
	return out, nil
}
