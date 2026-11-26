// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"context"
	"errors"
	"slices"

	"gopkg.in/yaml.v3"
)

func serviceNames(doc string) []string {
	var d struct {
		Services map[string]any `yaml:"services"`
	}
	_ = yaml.Unmarshal([]byte(doc), &d)
	return sortedKeys(d.Services)
}

// gitDoc: the Git document now running (the seeded one when there is no
// CD state).
func (a *fakeApp) gitDoc() string {
	if a.cd != nil {
		if d, ok := a.cd.docs[a.view.CD.Running]; ok {
			return d
		}
	}
	return string(a.sources[len(a.sources)-1].Document)
}

func (a *fakeApp) localConflicts() []string {
	if a.cd == nil || a.cd.local == "" {
		return nil
	}
	local := serviceNames(a.cd.local)
	var out []string
	for _, commit := range []string{a.view.CD.Running, a.view.CD.Candidate} {
		for _, s := range serviceNames(a.cd.docs[commit]) {
			if slices.Contains(local, s) && !slices.Contains(out, s) {
				out = append(out, s)
			}
		}
	}
	slices.Sort(out)
	return out
}

// mergeLocal: git's document with the local services added.
func mergeLocal(git, local string) ([]byte, error) {
	var g map[string]any
	if err := yaml.Unmarshal([]byte(git), &g); err != nil {
		return nil, err
	}
	if local != "" {
		var l struct {
			Services map[string]any `yaml:"services"`
		}
		if err := yaml.Unmarshal([]byte(local), &l); err != nil {
			return nil, err
		}
		svcs, _ := g["services"].(map[string]any)
		for k, v := range l.Services {
			svcs[k] = v
		}
	}
	return yaml.Marshal(g)
}

func (c *fakeConn) AppDeliveryLocal(ctx context.Context, tenant, app string) (AppCDLocal, error) {
	a, err := c.cdApp(ctx, "app-cd-local", tenant, app)
	if err != nil {
		return AppCDLocal{}, err
	}
	defer c.unlock()
	cur := a.cdView()
	out := AppCDLocal{Tenant: tenant, App: app, Revision: cur.Revision, LocalRevision: cur.LocalRevision, Services: []string{},
		GitServices: serviceNames(a.gitDoc()), Conflicts: a.localConflicts(), Registration: cur.Registration, Target: cur.LocalTarget}
	if a.cd != nil {
		out.Document = a.cd.local
		out.Actor = c.f.w.username(a.cd.localBy)
		if a.cd.local != "" {
			out.Services = serviceNames(a.cd.local)
		}
	}
	return out, nil
}

// applyAppLocal: put-app-local-services / clear-app-local-services, as
// mydcd: the local services document is an app upload named by the
// change; it waits for the next sync, which runs Git's document with these
// services added. Nothing runs now.
func (c *fakeConn) applyAppLocal(op UserOperation, actor string, next uint64) error {
	w := c.f.w
	ch := op.Change
	var q AppLocalChange
	if decodePayload(ch.Payload, &q) != nil || q.Tenant == "" || q.App == "" {
		return errors.New("payload")
	}
	clear := ch.Action == ActionClearAppLocalServices
	if clear != (q.Upload == "") || !clear && (q.Digest == ([32]byte{}) || len(q.Services) == 0 || !slices.IsSorted(q.Services)) {
		return errors.New("payload")
	}
	if !w.canManage(actor, q.Tenant) {
		return errForbidden
	}
	a := w.apps[q.Tenant+"/"+q.App]
	if a == nil || a.view.CD == nil || a.cd == nil || a.view.Retiring {
		return errCAS
	}
	cur := a.cdView()
	if ch.Expected > cur.Revision || q.Revision != cur.LocalRevision || q.Registration != cur.Registration || q.Target != nil && *q.Target != cur.LocalTarget || clear && a.cd.local == "" {
		return errCAS
	}
	doc := ""
	if !clear {
		u := w.uploads[q.Tenant+"/"+q.Upload]
		if u == nil || len(u.missing()) != 0 || u.view.App != q.App || u.view.Digest != q.Digest {
			return errCAS
		}
		doc = string(u.document())
		if !slices.Equal(serviceNames(doc), q.Services) {
			return errors.New("payload: service names")
		}
		gitNames := serviceNames(a.gitDoc())
		var l struct {
			Services map[string]struct {
				DependsOn any `yaml:"depends_on"`
			} `yaml:"services"`
			Rest map[string]any `yaml:",inline"`
		}
		if yaml.Unmarshal([]byte(doc), &l) != nil || len(l.Services) == 0 || len(l.Rest) > 1 || len(l.Rest) == 1 && l.Rest["name"] == nil {
			return errors.New("payload: only services")
		}
		for name, s := range l.Services {
			// A Git service cannot be changed, nor referenced.
			if slices.Contains(gitNames, name) || slices.ContainsFunc(words(s.DependsOn), func(d string) bool { return slices.Contains(gitNames, d) }) {
				return errors.New("payload: Git service")
			}
			if m, ok := s.DependsOn.(map[string]any); ok {
				for d := range m {
					if slices.Contains(gitNames, d) {
						return errors.New("payload: Git service")
					}
				}
			}
		}
		merged, err := mergeLocal(a.gitDoc(), doc)
		if err != nil {
			return errors.New("payload")
		}
		if _, err := parseApp(merged); err != nil {
			return errors.New("payload: " + err.Error())
		}
		delete(w.uploads, q.Tenant+"/"+q.Upload)
	}
	a.cd.local, a.cd.localBy = doc, actor
	a.cd.localRev++
	a.view.CD.Revision = next
	return nil
}
