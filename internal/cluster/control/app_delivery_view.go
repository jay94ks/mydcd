// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/json"
	"math"
	"slices"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
)

// CDRegistration returns owned public signed metadata, never requester secrets.
// The authenticated user edge also requires this exact stable user/current CD.
func (a Apps) CDRegistration(tenant, app string) (UserOperation, bool) {
	entry, exists := a.entries[appKey(tenant, app)]
	if !exists || entry.Delivery == nil || entry.Origin.Change.Action != "begin-app" {
		return UserOperation{}, false
	}
	raw, _ := json.Marshal(entry.Origin)
	var origin UserOperation
	if json.Unmarshal(raw, &origin) != nil {
		return UserOperation{}, false
	}
	return origin, true
}

type AppCDApprovalRegistration struct {
	Origin    UserOperation
	Selection AppApprovalSelection
	Realms    []string
}

type AppCDApprovalRequest struct {
	App       string
	Selection AppApprovalSelection
}

func (p Policy) AppDeliveryApprovalRegistration(s state.State, session access.Session, at int64, tenant string, q AppCDApprovalRequest) (AppCDApprovalRegistration, error) {
	p, err := p.Current(s)
	if err != nil {
		return AppCDApprovalRegistration{}, err
	}
	a, err := p.Apps(s)
	if err != nil {
		return AppCDApprovalRegistration{}, err
	}
	origin, exists := a.CDRegistration(tenant, q.App)
	if !exists || !q.Selection.Valid() {
		return AppCDApprovalRegistration{}, access.ErrDenied
	}
	b, err := p.appApprovalBlueprintFor(s, session, at, &origin, &q.Selection)
	if err != nil {
		return AppCDApprovalRegistration{}, err
	}
	uses, err := b.ApprovalUses(origin.Session.Key)
	if err != nil {
		return AppCDApprovalRegistration{}, err
	}
	out := AppCDApprovalRegistration{Origin: origin, Selection: q.Selection}
	if q.Selection.Candidate != nil {
		candidate := *q.Selection.Candidate
		out.Selection.Candidate = &candidate
	}
	for realm, items := range uses {
		if len(items) > 0 {
			out.Realms = append(out.Realms, realm)
		}
	}
	slices.Sort(out.Realms)
	return out, nil
}

// AppCDView is public selection/progress metadata. Source Ready/commit and a
// historical operation are deliberately separate from AppView's live health.
type AppCDView struct {
	LocalTarget                                [32]byte
	LocalActor                                 string             `json:",omitempty"`
	LocalServices                              []string           `json:",omitempty"`
	LocalRevision                              uint64             `json:",omitempty"`
	Approvers                                  []string           `json:",omitempty"` // user IDs (grant-cd-approver)
	Decision                                   *AppCDDecisionView `json:",omitempty"`
	Revision, PolicyRevision, OverrideRevision uint64
	Registration                               [32]byte
	Target                                     [32]byte
	Principal, SourceError                     string
	Paused                                     bool
	Policy                                     deployment.DeliveryDeclaration
	Candidate                                  *deployment.DeliverySelection  `json:",omitempty"`
	Running                                    *deployment.DeliverySelection  `json:",omitempty"`
	Transition                                 *deployment.DeliveryTransition `json:",omitempty"`
	Status                                     *deployment.DeliveryStatus     `json:",omitempty"`
	ChangeCount                                int                            `json:",omitempty"`
	OverrideCount                              int                            `json:",omitempty"`
	Blocked                                    string                         `json:",omitempty"`
}

func (p Policy) ObserveAppCD(s state.State, a Apps, c access.Catalog, row *AppView, now uint64) {
	if row.CD == nil {
		return
	}
	entry, exists := a.entries[appKey(row.Tenant, row.App)]
	if !exists || entry.Delivery == nil {
		row.CD.Blocked = "unavailable"
		return
	}
	if entry.CDDecision != nil {
		row.CD.Decision = entry.CDDecision.view()
	}
	ctx, err := p.AppPlanning(s, entry.Delivery.Principal(), row.Tenant)
	if err != nil {
		row.CD.Blocked = "current-inputs"
		return
	}
	ctx.Project, ctx.Deployment = row.App, row.Deployment
	if begin, err := appOriginBegin(entry.Origin, entry.Inventory.Scope()); err == nil {
		ctx.DefaultNode = begin.DefaultNode
	}
	status, err := entry.Delivery.Status(c, ctx, now)
	if err != nil {
		row.CD.Blocked = "current-authority"
		return
	}
	changes, diffErr := entry.Delivery.ServiceChanges()
	if diffErr != nil {
		row.CD.Blocked = "diff-unavailable"
		return
	}
	row.CD.ChangeCount = len(changes)
	status.Changes = nil // app pages remain bounded; full input diff uses app planning
	if entry.Delivery.SourceError() == "name-conflict" || entry.Delivery.SourceError() == "alias-conflict" {
		row.CD.Blocked = entry.Delivery.SourceError()
	} else if c.AuthorizeAccepted(entry.Origin.Session, p.Cluster, entry.Origin.At, row.Tenant, access.ManageCD, "") != nil {
		row.CD.Blocked = "current-authority"
	} else if !entry.Delivery.Paused() && status.Sync != "InSync" && now > 0 && now <= math.MaxInt64 {
		if candidate, ok := entry.Delivery.CandidateBlueprint(); ok && p.checkCDGroupApprovals(s, c, entry, candidate, int64(now)) != nil {
			row.CD.Blocked, status.Operation = "group-approval", "AwaitingApproval"
		}
	}
	row.CD.Status = &status
}

func appCDView(entry appEntry) *AppCDView {
	if entry.Delivery == nil {
		return nil
	}
	d := *entry.Delivery
	v := &AppCDView{Revision: d.Revision(), PolicyRevision: d.PolicyRevision(), OverrideRevision: d.OverrideRevision(), Registration: appRegistrationDigest(entry.Origin), Principal: d.Principal(), SourceError: d.SourceError(), Paused: d.Paused(), Policy: d.Policy()}
	v.LocalRevision = d.LocalRevision()
	v.Approvers = d.Approvers()
	v.LocalTarget = appLocalTarget(entry)
	if entry.LocalEdit != nil {
		v.LocalActor = entry.LocalEdit.Session.User
	}
	if entry.Local != nil {
		v.LocalServices = slices.Clone(entry.Local.Services)
	}
	v.Target = appSyncTarget(entry)
	v.OverrideCount = len(d.Overrides())
	if c, exists := d.CandidateSelection(); exists {
		v.Candidate = &c
	}
	if r, active := d.Selection(); active {
		v.Running = &r
	}
	if t, pending := d.Transition(); pending {
		v.Transition = &t
	}
	return v
}
