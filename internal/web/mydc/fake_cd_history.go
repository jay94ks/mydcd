// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/deployment"

	"gopkg.in/yaml.v3"
)

// REQ-46 in the fake. Each CD app keeps the app.yaml of the commits it has
// seen (cdDocs) and a history row per candidate. The fixture's running
// commit is the seeded document; its candidate is that document with the
// image of Fixture.ImageCandidates. Fake.SetCDCandidate injects a new Git
// commit. sync-app/recover-app finish at once (succeeded).

type cdState struct {
	docs    map[string]string // commit → app.yaml in Git
	history []CDHistoryRow
	seq     []uint64 // per history row, for newest-first paging
	next    uint64

	rejected map[string]bool // REQ-25 commits that do not come back
	head     string          // latest Git commit

	local    string // REQ-15 web-added services (fake_cd_local.go)
	localRev uint64
	localBy  string // user ID of the last local change
}

func (s *cdState) add(r CDHistoryRow) {
	s.next++
	s.history = append(s.history, r)
	s.seq = append(s.seq, s.next)
}

func (s *cdState) row(commit, result string) *CDHistoryRow {
	for i := len(s.history) - 1; i >= 0; i-- {
		if s.history[i].Commit == commit && (result == "" || s.history[i].Result == result) {
			return &s.history[i]
		}
	}
	return nil
}

// seedCDHistory: the fixture running commit (succeeded at accept) and
// candidate.
func (a *fakeApp) seedCDHistory(doc, candidateImage string, at int64) {
	cd := a.view.CD
	a.cd = &cdState{docs: map[string]string{}, rejected: map[string]bool{}, head: cd.Candidate}
	if cd.Running != "" {
		a.cd.docs[cd.Running] = doc
		a.cd.add(CDHistoryRow{Commit: cd.Running, CandidateDigest: candidateDigest(a.view.Tenant, a.view.App, cd.Running),
			PlannedAt: at, Result: CDSucceeded, Operation: "seed-" + a.view.App, FinishedAt: at})
	}
	if cd.Candidate != "" && cd.Candidate != cd.Running {
		a.cd.docs[cd.Candidate] = withImage(doc, candidateImage)
		a.cd.add(CDHistoryRow{Commit: cd.Candidate, CandidateDigest: candidateDigest(a.view.Tenant, a.view.App, cd.Candidate),
			PlannedAt: at + 60, Result: CDCandidate})
	}
}

// withImage: doc with the image of the service whose repository matches
// ref's swapped for ref.
func withImage(doc, ref string) string {
	repo := ref
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		repo = ref[:i]
	}
	var out []string
	for _, l := range strings.Split(doc, "\n") {
		t := strings.TrimSpace(l)
		if ref != "" && strings.HasPrefix(t, "image: "+repo+":") {
			l = l[:strings.Index(l, "image:")] + "image: " + ref
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

// SetCDCandidate puts a new Git commit of a CD app's source as its
// candidate: the previous unapplied candidate is abandoned.
func (f *Fake) SetCDCandidate(tenant, app, commit, doc string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w := f.w
	a := w.apps[tenant+"/"+app]
	if a == nil || a.view.CD == nil || a.cd == nil {
		panic("mydc fake: not a CD app " + tenant + "/" + app)
	}
	a.cd.docs[commit], a.cd.head = doc, commit
	if a.cd.rejected[commit] {
		return // only a new commit or replan-app brings it back
	}
	if r := a.cd.row(a.view.CD.Candidate, CDCandidate); r != nil {
		r.Result, r.Reason = CDAbandoned, "superseded"
	}
	w.root++
	a.view.CD.Candidate, a.view.CD.Revision = commit, w.root
	w.cdCandidate(a, commit, f.now().Unix())
}

// cdCandidate adds the history row and events of a new candidate.
func (w *world) cdCandidate(a *fakeApp, commit string, now int64) {
	a.cd.add(CDHistoryRow{Commit: commit, CandidateDigest: candidateDigest(a.view.Tenant, a.view.App, commit), PlannedAt: now, Result: CDCandidate})
	w.cdEvent(a, EventCDCandidateCreated, commit, "", "", "", now)
	if a.view.CD.Mode == "manual" {
		w.cdEvent(a, EventCDApprovalRequired, commit, "", "", "", now)
	}
}

// cdSynced records sync-app/recover-app applying the candidate.
func (a *fakeApp) cdSynced(commit, operation string, now int64) {
	if a.cd == nil {
		return
	}
	r := a.cd.row(commit, CDCandidate)
	if r == nil {
		a.cd.add(CDHistoryRow{Commit: commit, CandidateDigest: candidateDigest(a.view.Tenant, a.view.App, commit), PlannedAt: now})
		r = &a.cd.history[len(a.cd.history)-1]
	}
	r.Result, r.Reason, r.Operation, r.FinishedAt = CDSucceeded, "", operation, now
}

func cdParse(doc string) map[string]any {
	var m map[string]any
	if yaml.Unmarshal([]byte(doc), &m) != nil {
		return nil
	}
	return m
}

func cdLookup(m map[string]any, path []string) (any, bool) {
	var cur any = m
	for _, p := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = mm[p]; !ok {
			return nil, false
		}
	}
	return cur, true
}

func rawJSON(v any, ok bool) json.RawMessage {
	if !ok {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}

// cdFlatten: leaf paths of a service (maps are walked, anything else is a
// leaf).
func cdFlatten(prefix []string, v any, out map[string]any) {
	if m, ok := v.(map[string]any); ok && len(m) > 0 {
		for k, x := range m {
			cdFlatten(append(slices.Clone(prefix), k), x, out)
		}
		return
	}
	out[strings.Join(prefix, "\x00")] = v
}

// cdChanges compares the running and candidate documents.
func (a *fakeApp) cdChanges() CDChanges {
	cd := a.view.CD
	out := CDChanges{Tenant: a.view.Tenant, App: a.view.App, Running: cd.Running, Candidate: cd.Candidate, Services: []CDServiceChange{}, Added: []string{}, Removed: []string{}}
	if a.cd == nil || cd.Candidate == "" || cd.Candidate == cd.Running {
		return out
	}
	before, _ := cdLookup(cdParse(a.cd.docs[cd.Running]), []string{"services"})
	after, _ := cdLookup(cdParse(a.cd.docs[cd.Candidate]), []string{"services"})
	bs, _ := before.(map[string]any)
	as, _ := after.(map[string]any)
	names := map[string]bool{}
	for k := range bs {
		names[k] = true
	}
	for k := range as {
		names[k] = true
	}
	for _, svc := range sortedKeys(names) {
		b, inB := bs[svc]
		x, inA := as[svc]
		switch {
		case !inB:
			out.Added = append(out.Added, svc)
			continue
		case !inA:
			out.Removed = append(out.Removed, svc)
			continue
		}
		fb, fa := map[string]any{}, map[string]any{}
		cdFlatten(nil, b, fb)
		cdFlatten(nil, x, fa)
		keys := map[string]bool{}
		for k := range fb {
			keys[k] = true
		}
		for k := range fa {
			keys[k] = true
		}
		var fields []CDFieldChange
		for _, k := range sortedKeys(keys) {
			vb, okB := fb[k]
			va, okA := fa[k]
			if okB && okA && reflect.DeepEqual(vb, va) {
				continue
			}
			fields = append(fields, CDFieldChange{Path: append([]string{"services", svc}, strings.Split(k, "\x00")...), Before: rawJSON(vb, okB), After: rawJSON(va, okA)})
		}
		if len(fields) > 0 {
			out.Services = append(out.Services, CDServiceChange{Service: svc, Fields: fields})
			out.Count += len(fields)
		}
	}
	out.Count += len(out.Added) + len(out.Removed)
	return out
}

func (c *fakeConn) cdApp(ctx context.Context, m, tenant, app string) (*fakeApp, error) {
	if err := c.appRead(ctx, m, tenant); err != nil {
		return nil, err
	}
	a := c.f.w.apps[tenant+"/"+app]
	if a == nil || a.view.CD == nil {
		c.unlock()
		return nil, fail(m, CodeInvalid, "not a CD app")
	}
	return a, nil
}

// AppDeliveryHistory: candidates newest first.
func (c *fakeConn) AppDeliveryHistory(ctx context.Context, tenant, app, after string) (Page[CDHistoryRow], error) {
	const m = "app-cd-history"
	if err := checkAfter(m, after); err != nil {
		return Page[CDHistoryRow]{}, err
	}
	a, err := c.cdApp(ctx, m, tenant, app)
	if err != nil {
		return Page[CDHistoryRow]{}, err
	}
	defer c.unlock()
	type keyed struct {
		k string
		r CDHistoryRow
	}
	var rows []keyed
	if a.cd != nil {
		for i, r := range a.cd.history {
			if r.Result == CDCandidate && r.Commit == a.view.CD.Candidate && a.view.CD.Blocked != "" {
				r.Result, r.Reason = CDBlocked, a.view.CD.Blocked
			}
			rows = append(rows, keyed{fmt.Sprintf("%016x", ^a.cd.seq[i]), r})
		}
	}
	p := paginate(rows, func(k keyed) string { return k.k }, after, c.f.pageSize, a.view.CD.Revision)
	out := Page[CDHistoryRow]{Revision: p.Revision, Next: p.Next, Items: []CDHistoryRow{}}
	for _, k := range p.Items {
		out.Items = append(out.Items, k.r)
	}
	return out, nil
}

// AppDeliveryValues: one app-cd-field path in Git and now.
func (c *fakeConn) AppDeliveryValues(ctx context.Context, tenant string, q control.AppCDFieldRequest) (CDFieldValues, error) {
	const m = "app-cd-values"
	if !deployment.AllowedAppOverride(q.Path) {
		if _, err := c.lockSession(ctx, m); err != nil {
			return CDFieldValues{}, err
		}
		c.unlock()
		return CDFieldValues{}, fail(m, CodeDenied, "")
	}
	a, err := c.cdApp(ctx, m, tenant, q.App)
	if err != nil {
		return CDFieldValues{}, err
	}
	defer c.unlock()
	cd := a.view.CD
	out := CDFieldValues{Tenant: tenant, App: q.App, Path: slices.Clone(q.Path), Running: cd.Running}
	run := cdParse(string(a.sources[len(a.sources)-1].Document))
	if a.cd != nil {
		if d, ok := a.cd.docs[cd.Running]; ok {
			run = cdParse(d)
		}
		out.GitRunning = rawJSON(cdLookup(run, q.Path))
		if cd.Candidate != "" && cd.Candidate != cd.Running {
			out.Candidate = cd.Candidate
			out.GitCandidate = rawJSON(cdLookup(cdParse(a.cd.docs[cd.Candidate]), q.Path))
		}
	}
	out.Current = rawJSON(cdLookup(run, q.Path))
	for _, o := range a.cdOverrides {
		if slices.Equal(o.Path, q.Path) {
			out.Current, out.Overridden = slices.Clone(o.Value), true
		}
	}
	// An environment key Git does not set may come from secrets_from:
	// name the selectors, never a value.
	if q.Path[2] == "environment" && out.GitRunning == nil && !out.Overridden {
		if v, ok := cdLookup(run, []string{"services", q.Path[1], "x-mydc", "secrets_from"}); ok {
			l, _ := v.([]any)
			for _, s := range l {
				if text, ok := s.(string); ok {
					text = strings.TrimPrefix(text, "cluster/")
					if id, group := strings.CutPrefix(text, "group/"); group {
						out.Secrets = append(out.Secrets, "group:"+id)
					} else {
						out.Secrets = append(out.Secrets, "secret:"+text)
					}
				}
			}
		}
	}
	return out, nil
}

// AppDeliveryChanges: running → candidate.
func (c *fakeConn) AppDeliveryChanges(ctx context.Context, tenant, app string) (CDChanges, error) {
	a, err := c.cdApp(ctx, "app-cd-changes", tenant, app)
	if err != nil {
		return CDChanges{}, err
	}
	defer c.unlock()
	return a.cdChanges(), nil
}
