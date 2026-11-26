// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"context"
	"encoding/json"
	"slices"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/userauth"
)

// CD screens over mydcd's app-cd-history, app-cd-diff and app-cd-field
// reads (W1.2 step 2e), in the web's screen form.

func (c *realConn) AppDeliveryHistory(ctx context.Context, tenant, app, after string) (Page[CDHistoryRow], error) {
	p, err := realCall(ctx, c, "app-cd-history", func(u userauth.Client, s access.Session) (control.AppCDHistoryPage, error) {
		return u.AppDeliveryHistory(ctx, c.peer, s, tenant, app, after)
	})
	if err != nil {
		return Page[CDHistoryRow]{}, err
	}
	items := make([]CDHistoryRow, 0, len(p.Records))
	for _, r := range p.Records {
		items = append(items, cdHistoryRow(r))
	}
	return Page[CDHistoryRow]{Items: items, Next: p.Next}, nil
}

// cdHistoryRow: mydcd's "executing" is the screen's running; an approver's
// reason is the note, a rejecter's the reason.
func cdHistoryRow(r control.AppCDHistoryRecord) CDHistoryRow {
	v := CDHistoryRow{Commit: r.Commit, CandidateDigest: r.Candidate, PlannedAt: int64(r.PlannedAt), Result: r.Status, Operation: r.Operation,
		FinishedAt: int64(r.CompletedAt), Actor: r.Actor, Reason: r.Code}
	switch r.Status {
	case "executing":
		v.Result = CDRunning
	case CDFailed, "rejected":
		v.Result = CDFailed
		if r.Reason != "" {
			v.Reason = r.Reason
		}
	default:
		v.Note = r.Reason
	}
	return v
}

func (c *realConn) AppDeliveryChanges(ctx context.Context, tenant, app string) (CDChanges, error) {
	d, err := realCall(ctx, c, "app-cd-diff", func(u userauth.Client, s access.Session) (control.AppCDDiff, error) {
		return u.AppDeliveryDiff(ctx, c.peer, s, tenant, app)
	})
	if err != nil {
		return CDChanges{}, err
	}
	return cdChanges(d), nil
}

func cdChanges(d control.AppCDDiff) CDChanges {
	out := CDChanges{Tenant: d.Tenant, App: d.App, Candidate: d.Candidate.Commit, Count: d.ChangeCount, Services: []CDServiceChange{}, Added: []string{}, Removed: []string{}}
	if d.Running != nil {
		out.Running = d.Running.Commit
	}
	value := func(v deployment.PublicFieldValue) json.RawMessage {
		if !v.Present {
			return nil
		}
		return v.Value
	}
	for _, ch := range d.Changes {
		switch {
		case ch.Action == "added" && len(ch.Path) <= 2:
			if !slices.Contains(out.Added, ch.Service) {
				out.Added = append(out.Added, ch.Service)
			}
			continue
		case ch.Action == "removed" && len(ch.Path) <= 2:
			if !slices.Contains(out.Removed, ch.Service) {
				out.Removed = append(out.Removed, ch.Service)
			}
			continue
		}
		i := slices.IndexFunc(out.Services, func(s CDServiceChange) bool { return s.Service == ch.Service })
		if i < 0 {
			out.Services = append(out.Services, CDServiceChange{Service: ch.Service})
			i = len(out.Services) - 1
		}
		out.Services[i].Fields = append(out.Services[i].Fields, CDFieldChange{Path: slices.Clone(ch.Path), Before: value(ch.Before), After: value(ch.After)})
	}
	return out
}

// AppDeliveryValues: the field's value in Git at the candidate (Source) and
// running commits, and the value in force. Secret projections never come
// back from mydcd.
func (c *realConn) AppDeliveryValues(ctx context.Context, tenant string, q control.AppCDFieldRequest) (CDFieldValues, error) {
	const m = "app-cd-field"
	f, err := realCall(ctx, c, m, func(u userauth.Client, s access.Session) (control.AppCDField, error) {
		return u.AppDeliveryField(ctx, c.peer, s, tenant, q)
	})
	if err != nil {
		return CDFieldValues{}, err
	}
	out := CDFieldValues{Tenant: f.Tenant, App: f.App, Path: slices.Clone(f.Path)}
	v := f.Values
	if v == nil {
		return out, nil
	}
	pick := func(p deployment.PublicFieldValue) json.RawMessage {
		if !p.Present {
			return nil
		}
		return p.Value
	}
	out.Candidate, out.Running = v.SourceCommit, v.CurrentCommit
	out.GitCandidate, out.GitRunning, out.Current, out.Overridden = pick(v.Source), pick(v.RunningSource), pick(v.Current), v.Overridden
	return out, nil
}

// AppDeliveryLocal: the CD row's local services (AppCDView) and the
// pending document (app-source section pending-local). GitServices are the
// running version's source document's services.
func (c *realConn) AppDeliveryLocal(ctx context.Context, tenant, app string) (AppCDLocal, error) {
	const m = "app-cd-local"
	var cd *AppCD
	for after := ""; ; {
		p, err := c.Apps(ctx, tenant, after)
		if err != nil {
			return AppCDLocal{}, err
		}
		if i := slices.IndexFunc(p.Items, func(a AppView) bool { return a.App == app }); i >= 0 {
			cd = p.Items[i].CD
			break
		}
		if p.Next == "" {
			break
		}
		after = p.Next
	}
	if cd == nil {
		return AppCDLocal{}, fail(m, CodeMissing, "no such app with automatic deployment")
	}
	out := AppCDLocal{Tenant: tenant, App: app, Revision: cd.Revision, LocalRevision: cd.LocalRevision, Actor: cd.LocalActor,
		Services: slices.Clone(cd.LocalServices), Registration: cd.Registration, Target: cd.LocalTarget}
	if out.Services == nil {
		out.Services = []string{}
	}
	if len(cd.LocalServices) > 0 {
		raw, err := realCall(ctx, c, m, func(u userauth.Client, s access.Session) ([]byte, error) {
			raw, _, err := u.ReadAppSource(ctx, c.peer, s, tenant, control.AppSourceSelection{App: app, Section: "pending-local"})
			return raw, err
		})
		if err != nil {
			return AppCDLocal{}, err
		}
		out.Document = string(raw)
	}
	src, err := c.AppSource(ctx, tenant, app, 0)
	if err != nil {
		return AppCDLocal{}, err
	}
	out.GitServices = composeServiceNames(src.Document)
	for _, n := range out.Services {
		if slices.Contains(out.GitServices, n) {
			out.Conflicts = append(out.Conflicts, n)
		}
	}
	return out, nil
}

// composeServiceNames: the sorted service names of an app document (none
// when it does not parse).
func composeServiceNames(doc []byte) []string {
	d, err := deployment.ParseApp(doc)
	out := []string{}
	if err != nil {
		return out
	}
	for name := range d.Services {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}
