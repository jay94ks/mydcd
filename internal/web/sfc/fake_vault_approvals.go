// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"sort"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/secrets"
)

// Group approvals in the fake. A Group needs approval when it has a
// password (a published verifier write, or Fake.SetGroupPassword) and a
// service of the app names it in `x-sfc.secrets.from: [group/ID]`
// (tenant scope). Approvals are kept per (realm, group, begin-app request),
// and begin-app is refused (ResultInvalid) while one is missing, as sfcd
// refuses an unapproved protected Group use. A begin-image-build original
// works the same way for the build context's secret mounts (f4e1a7e):
// begin-image-build is refused (ResultInvalid) until each protected Group
// is approved for that original's request ID.

// SetGroupPassword sets (password != "") or clears a Group's password.
func (f *Fake) SetGroupPassword(realm, group, password string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if password == "" {
		delete(f.w.groupVerifiers, realm+"/"+group)
		return
	}
	v := fakeGroupVerifier(password)
	f.w.groupVerifiers[realm+"/"+group] = v
}

// GroupApproved reports whether the fake holds an approval of a Group for
// the begin-app original with this request ID (for a CD candidate:
// "cd-{tenant}-{app}/{candidate hex}"), for tests.
func (f *Fake) GroupApproved(realm, group, requestID string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.w.approvals[approvalKey(realm, group, requestID)]
	return ok
}

func approvalKey(realm, group, requestID string) string { return realm + "/" + group + "/" + requestID }

// groupUses is the protected Groups an uploaded document's services use:
// group → services (sorted), plus each service's node.
func (w *world) groupUses(tenant string, doc []byte) (map[string][]string, map[string]string) {
	var d struct {
		Services map[string]struct {
			XSfc struct {
				Node    string `yaml:"node"`
				Secrets struct {
					From deployment.SecretSources `yaml:"from"`
				} `yaml:"secrets"`
			} `yaml:"x-sfc"`
		} `yaml:"services"`
	}
	uses, nodes := map[string][]string{}, map[string]string{}
	if yaml.Unmarshal(doc, &d) != nil {
		return uses, nodes
	}
	for svc, s := range d.Services {
		nodes[svc] = s.XSfc.Node
		for _, src := range s.XSfc.Secrets.From {
			if src.Group == "" || src.Scope == "cluster" {
				continue
			}
			if _, ok := w.groupVerifiers[tenant+"/"+src.Group]; ok && !slices.Contains(uses[src.Group], svc) {
				uses[src.Group] = append(uses[src.Group], svc)
			}
		}
	}
	for g := range uses {
		sort.Strings(uses[g])
	}
	return uses, nodes
}

// originUses decodes a begin-app original and the protected Groups its
// upload uses; with a selection, the CD candidate's (the fake's candidate
// is the app's current document). A begin-volume-move original stands for
// its move's uploaded document.
func (w *world) originUses(origin *UserOperation, sel *AppApprovalSelection) (control.AppBegin, map[string][]string, map[string]string, bool) {
	var b control.AppBegin
	if origin != nil && origin.Change.Action == ActionBeginVolumeMove && sel == nil {
		// a move's original: the uploaded target document under the move ID
		var q control.VolumeMoveBegin
		if json.Unmarshal(origin.Change.Payload, &q) != nil || q.App == nil || q.App.Target == nil {
			return b, nil, nil, false
		}
		mv := w.moves[moveKey(q.Scope)]
		u := w.uploads[q.Scope.Tenant+"/"+q.App.Target.Upload]
		if mv == nil || mv.op.RequestID != origin.RequestID || u == nil || len(u.missing()) != 0 {
			return b, nil, nil, false
		}
		b = control.AppBegin{Tenant: q.Scope.Tenant, App: q.Scope.App, Upload: q.App.Target.Upload, Operation: q.ID}
		uses, nodes := w.groupUses(b.Tenant, artifactDocument(u.document()))
		return b, uses, nodes, true
	}
	if origin != nil && origin.Change.Action == ActionBeginImageBuild {
		return w.buildOriginUses(origin, sel)
	}
	if origin != nil && origin.Change.Action == ActionBindExternalRegistry {
		return w.extOriginUses(origin, sel)
	}
	if origin != nil && origin.Change.Action == ActionStandaloneUp {
		// a standalone-up original stands for its uploaded service.
		if sel != nil || json.Unmarshal(origin.Change.Payload, &b) != nil || b.Standalone == nil {
			return b, nil, nil, false
		}
		u := w.uploads[b.Tenant+"/"+b.Upload]
		if u == nil || len(u.missing()) != 0 {
			return b, nil, nil, false
		}
		uses, nodes := w.groupUses(b.Tenant, u.document())
		return b, uses, nodes, true
	}
	if origin == nil || origin.Change.Action != ActionBeginApp || json.Unmarshal(origin.Change.Payload, &b) != nil {
		return b, nil, nil, false
	}
	if sel != nil {
		a := w.apps[b.Tenant+"/"+b.App]
		if a == nil || a.view.CD == nil || a.view.CD.Candidate == "" || sel.Candidate == nil || *sel.Candidate != candidateDigest(b.Tenant, b.App, a.view.CD.Candidate) || len(a.sources) == 0 {
			return b, nil, nil, false
		}
		uses, nodes := w.groupUses(b.Tenant, a.sources[len(a.sources)-1].Document)
		return b, uses, nodes, true
	}
	u := w.uploads[b.Tenant+"/"+b.Upload]
	if u == nil || len(u.missing()) != 0 {
		return b, nil, nil, false
	}
	uses, nodes := w.groupUses(b.Tenant, u.document())
	return b, uses, nodes, true
}

// buildOriginUses: a begin-image-build original (as sfcd's
// imageBuildApprovalUses) stands for its job's builder. App is
// control.ImageBuildSecretScope(tenant, context), Deployment the job ID,
// the one service "builder" on the build server. A protected Group is a
// Group (with a password) the mounted Secret is tagged with or under.
func (w *world) buildOriginUses(origin *UserOperation, sel *AppApprovalSelection) (control.AppBegin, map[string][]string, map[string]string, bool) {
	var q control.ImageBuildJobStart
	if sel != nil || origin.Change.Expected != 0 || json.Unmarshal(origin.Change.Payload, &q) != nil || q.Tenant == "" || q.Context == "" || q.ID == "" || q.Version == ([32]byte{}) || q.Snapshot == ([32]byte{}) || q.At == 0 {
		return control.AppBegin{}, nil, nil, false
	}
	x, n, _, ok := w.findVersion(q.Tenant, q.Version)
	if !ok || x.row.ID != q.Context {
		return control.AppBegin{}, nil, nil, false
	}
	spec, ok := w.jobSpec(x, q.ID, n, q.At)
	if !ok || spec.Digest() != q.Snapshot {
		return control.AppBegin{}, nil, nil, false
	}
	b := control.AppBegin{Tenant: q.Tenant, App: control.ImageBuildSecretScope(q.Tenant, q.Context), Deployment: q.ID, DefaultNode: spec.Scope.Root.Node}
	uses := map[string][]string{}
	for _, m := range spec.Context.Secrets {
		if m.Realm != q.Tenant {
			continue
		}
		i := slices.IndexFunc(w.vault, func(v VaultView) bool { return v.Realm == m.Realm && v.ID == m.Secret && v.Kind == "object" })
		if i < 0 {
			continue
		}
		v := w.vault[i]
		for _, g := range append([]string{v.Group}, w.vaultAncestors(m.Realm, v.Parent)...) {
			if _, ok := w.groupVerifiers[m.Realm+"/"+g]; ok && g != "" && len(uses[g]) == 0 {
				uses[g] = []string{"builder"}
			}
		}
	}
	return b, uses, map[string]string{"builder": b.DefaultNode}, true
}

func candidateDigest(tenant, app, commit string) [32]byte {
	return sha256.Sum256([]byte("cd-candidate\x00" + tenant + "/" + app + "@" + commit))
}

// approvalReq names what an approval is for: the begin-app request, and
// the candidate when one is selected.
func approvalReq(origin *UserOperation, sel *AppApprovalSelection) string {
	if sel != nil && sel.Candidate != nil {
		return origin.RequestID + "/" + hex.EncodeToString(sel.Candidate[:])
	}
	return origin.RequestID
}

// AppDeliveryRegistration: the app's registrant (the fake's submitter of
// the app) reads a synthetic registered origin; only a candidate selection
// is modeled.
func (c *fakeConn) AppDeliveryRegistration(ctx context.Context, tenant, app string, sel AppApprovalSelection) (AppCDRegistration, error) {
	const m = "app-cd-registration"
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return AppCDRegistration{}, err
	}
	defer c.unlock()
	w := c.f.w
	a := w.apps[tenant+"/"+app]
	if a == nil || a.view.CD == nil || len(a.sources) == 0 || sel.Candidate == nil {
		return AppCDRegistration{}, fail(m, CodeDenied, "")
	}
	registrant := ""
	for id, u := range w.users {
		if u.rec.Username == a.sources[len(a.sources)-1].Submitter {
			registrant = id
		}
	}
	if registrant != user || !w.canManage(user, tenant) {
		return AppCDRegistration{}, fail(m, CodeDenied, "")
	}
	payload, _ := json.Marshal(control.AppBegin{Tenant: tenant, App: app, Upload: "cd", Operation: "cd"})
	origin := UserOperation{Schema: 1, RequestID: "cd-" + tenant + "-" + app, Change: Change{Schema: 1, Action: ActionBeginApp, Principal: user, Payload: payload}}
	origin.Session.User, origin.Session.Key = user, pub32(FixtureKey("cd-"+user))
	_, uses, _, ok := w.originUses(&origin, &sel)
	if !ok {
		return AppCDRegistration{}, fail(m, CodeDenied, "")
	}
	reg := AppCDRegistration{Origin: origin, Selection: sel}
	if len(uses) > 0 {
		reg.Realms = []string{tenant}
	}
	return reg, nil
}

func (w *world) approvalTarget(b control.AppBegin, origin *UserOperation, sel *AppApprovalSelection, group string, services []string, nodes map[string]string) secrets.Target {
	t := secrets.Target{Cluster: w.cluster, Realm: b.Tenant, Tenant: b.Tenant, User: origin.Session.User, RequesterKey: origin.Session.Key,
		App: b.App, Deployment: b.Deployment, Group: group, Services: slices.Clone(services), Actions: [2]string{"read", "deploy"}, Scope: "app"}
	if origin.Change.Action == ActionBeginImageBuild {
		t.Purpose, t.Actions, t.Scope = secrets.PurposeImageBuild, [2]string{"resolve", "build"}, "selected-secrets-in-group-namespace"
	}
	if origin.Change.Action == ActionBindExternalRegistry {
		t.Purpose, t.Actions, t.Scope = secrets.PurposeRegistrySource, [2]string{"resolve", "registry"}, "selected-secrets-in-group-namespace"
	}
	seen := map[string]bool{}
	for _, svc := range services {
		n := nodes[svc]
		if n == "" {
			n = b.DefaultNode
		}
		if n != "" && !seen[n] {
			seen[n] = true
			t.Nodes = append(t.Nodes, secrets.NodeScope{ID: n, Key: pub32(FixtureKey(n))})
		}
	}
	sum := sha256.Sum256([]byte(approvalKey(b.Tenant, group, approvalReq(origin, sel))))
	t.ApprovalID = "approval-" + hex.EncodeToString(sum[:24])
	return t
}

func (c *fakeConn) PlanVaultApprovals(ctx context.Context, tenant string, q VaultApprovalPlanRequest) (VaultApprovalPlan, error) {
	const m = "vault-approval-plan"
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return VaultApprovalPlan{}, err
	}
	defer c.unlock()
	w := c.f.w
	b, uses, nodes, ok := w.originUses(q.Origin, q.Selection)
	if !ok || q.Origin.Session.User != user || b.Tenant != tenant || q.Realm != tenant || !w.canRead(user, tenant) || (q.Origin.Change.Action == ActionBeginImageBuild || q.Origin.Change.Action == ActionBindExternalRegistry) && !w.canManage(user, tenant) {
		return VaultApprovalPlan{}, fail(m, CodeDenied, "")
	}
	if len(uses) == 0 {
		return VaultApprovalPlan{}, fail(m, CodeDenied, "") // no use in this realm
	}
	plan := VaultApprovalPlan{Realm: q.Realm}
	for _, g := range sortedKeys(uses) {
		t := w.approvalTarget(b, q.Origin, q.Selection, g, uses[g], nodes)
		v := VaultApprovalTarget{Target: t, Approver: &config.Peer{ID: "node-a", Key: keyHex(FixtureKey("node-a")), Endpoint: "10.0.0.11:7443"}}
		if _, done := w.approvals[approvalKey(b.Tenant, g, approvalReq(q.Origin, q.Selection))]; done {
			v.Existing = &secrets.Approval{Schema: 1, Payload: secrets.ApprovalPayload{Target: t}}
		}
		plan.Targets = append(plan.Targets, v)
	}
	return plan, nil
}

func (c *fakeConn) ApproveVault(ctx context.Context, tenant string, approver config.Peer, q VaultApprove) (string, error) {
	const m = "secret-input"
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return "", err
	}
	defer c.unlock()
	w := c.f.w
	b, uses, nodes, ok := w.originUses(q.Origin, q.Selection)
	if !ok || approver.ID != "node-a" || q.Target.User != user || q.Target.Realm != tenant || b.Tenant != tenant || len(uses[q.Target.Group]) == 0 ||
		(q.Origin.Change.Action == ActionBeginImageBuild || q.Origin.Change.Action == ActionBindExternalRegistry) && !w.canManage(user, tenant) {
		return "denied", nil
	}
	want := w.approvalTarget(b, q.Origin, q.Selection, q.Target.Group, uses[q.Target.Group], nodes)
	a, _ := json.Marshal(want)
	g, _ := json.Marshal(q.Target)
	if string(a) != string(g) {
		return "denied", nil
	}
	v, ok := w.groupVerifiers[tenant+"/"+q.Target.Group]
	if !ok || !v.Verify(q.Password) {
		return "denied", nil
	}
	w.approvals[approvalKey(tenant, q.Target.Group, approvalReq(q.Origin, q.Selection))] = want
	w.recordApproval(want, approver.ID, c.f.now().Unix())
	return "ok", nil
}

// missingApprovals: the protected Groups a begin-app (or
// begin-image-build) original still needs.
func (w *world) missingApprovals(op UserOperation) []string {
	b, uses, _, ok := w.originUses(&op, nil)
	if !ok {
		return nil
	}
	var out []string
	for _, g := range sortedKeys(uses) {
		if _, done := w.approvals[approvalKey(b.Tenant, g, op.RequestID)]; !done {
			out = append(out, g)
		}
	}
	return out
}

// fakeGroupVerifier hashes a Group password once per process: the hash is
// slow on purpose and every fake built from the fixture needs it.
var groupVerifierCache sync.Map // password → identity.PasswordVerifier

func fakeGroupVerifier(password string) identity.PasswordVerifier {
	if v, ok := groupVerifierCache.Load(password); ok {
		return v.(identity.PasswordVerifier)
	}
	v, err := identity.PasswordHash([]byte(password), []byte("fake-salt-000000"), identity.DefaultPasswordCost())
	if err != nil {
		panic(err)
	}
	groupVerifierCache.Store(password, v)
	return v
}
