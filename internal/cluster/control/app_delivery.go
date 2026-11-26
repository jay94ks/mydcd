// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"slices"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
)

// AppDeliveryInput is a read-only source transfer held by one registered fetch
// ticket. The bytes use the existing bounded Upload; it is not an app operation.
type AppDeliveryInput struct {
	Ticket         deployment.DeliveryFetch
	Upload, Commit string
}

type AppDeliveryProgress struct {
	Schema                            uint8
	Kind                              string
	Cluster, Reporter                 [32]byte
	Tenant, App, Action               string
	Expected, RootRevision, Epoch, At uint64
	TargetCAS                         bool                      `json:",omitempty"`
	Target                            *[32]byte                 `json:",omitempty"`
	Ticket                            *deployment.DeliveryFetch `json:",omitempty"`
	Input                             *AppDeliveryInput         `json:",omitempty"`
	Begin                             *AppUploadBegin           `json:",omitempty"`
	Part                              *AppUploadPart            `json:",omitempty"`
	Error                             string                    `json:",omitempty"`
	Choice                            *AppDeliveryChoice        `json:",omitempty"`
	Signature                         []byte
}

func AppDeliveryProgressBytes(r AppDeliveryProgress) []byte {
	r.Signature = nil
	b, _ := json.Marshal(r)
	return append([]byte("mydc-app-delivery-progress-1\x00"), b...)
}
func (r AppDeliveryProgress) Command() (state.Command, error) {
	target := ""
	if r.TargetCAS {
		target = state.AppDeliveryTarget
	}
	b, err := json.Marshal(r)
	if err != nil {
		return state.Command{}, err
	}
	cmd := state.Command{Kind: state.ModuleReport, Actor: "node/" + hex.EncodeToString(r.Reporter[:]), Epoch: r.Epoch, Key: AppsKey, Expected: r.RootRevision, Target: target, Value: string(b)}
	cmd.RequestID = state.ReportRequestID(cmd)
	_, err = state.EncodeCommand(cmd)
	return cmd, err
}
func appDeliveryReportValue(raw []byte) bool {
	var kind struct{ Kind string }
	return json.Unmarshal(raw, &kind) == nil && kind.Kind == "app-delivery"
}
func (p Policy) appDeliveryProgress(s state.State, cmd state.Command) (AppDeliveryProgress, error) {
	var r AppDeliveryProgress
	if cmd.Kind != state.ModuleReport || cmd.Key != AppsKey || canonical([]byte(cmd.Value), &r) != nil || r.Schema != 1 || r.Kind != "app-delivery" || r.Cluster != p.Cluster || r.Reporter == ([32]byte{}) || r.Epoch != s.ModuleEpoch() || r.Expected == 0 || r.At == 0 || r.At > math.MaxInt64 || r.Tenant == "" || r.App == "" || !ed25519.Verify(ed25519.PublicKey(r.Reporter[:]), AppDeliveryProgressBytes(r), r.Signature) {
		return r, ErrCatalog
	}
	// Historical commands retain their original empty Target, request ID and
	// strict module-root CAS. New reports use only this explicit typed target.
	if cmd.Target != "" && cmd.Target != state.AppDeliveryTarget {
		return r, ErrCatalog
	}
	if r.Target != nil && (!r.TargetCAS || *r.Target == ([32]byte{})) {
		return r, ErrCatalog
	}
	original, err := r.Command()
	members, memberErr := p.Members(s)
	if err != nil || original != cmd || memberErr != nil || !members.MemberKey(r.Reporter) {
		return r, ErrCatalog
	}
	if (r.Action == "auto-sync" || r.Action == "replan" || r.Action == "continue" || r.Action == "fetch" || r.Action == "input") && !members.WorkKey(r.Reporter) {
		return r, ErrCatalog
	}
	switch r.Action {
	case "auto-sync":
		if r.Choice == nil || r.Ticket != nil || r.Input != nil || r.Begin != nil || r.Part != nil || r.Error != "" {
			return r, ErrCatalog
		}
	case "replan", "continue":
		if r.Choice != nil || r.Ticket != nil || r.Input != nil || r.Begin != nil || r.Part != nil || r.Error != "" {
			return r, ErrCatalog
		}
	case "fetch":
		if r.Ticket != nil || r.Input != nil || r.Begin != nil || r.Part != nil || r.Error != "" {
			return r, ErrCatalog
		}
	case "input":
		if r.Ticket == nil || r.Input == nil || r.Begin == nil || r.Part != nil || r.Error != "" {
			return r, ErrCatalog
		}
	case "part":
		if r.Ticket == nil || r.Part == nil || r.Input != nil || r.Begin != nil || r.Error != "" {
			return r, ErrCatalog
		}
	case "received":
		if r.Ticket == nil || r.Part != nil || r.Input != nil || r.Begin != nil || r.Error != "" {
			return r, ErrCatalog
		}
	case "source-error":
		if r.Ticket == nil || r.Part != nil || r.Input != nil || r.Begin != nil || r.Error == "" {
			return r, ErrCatalog
		}
	default:
		return r, ErrCatalog
	}
	if r.Action != "auto-sync" && r.Choice != nil {
		return r, ErrCatalog
	}
	return r, nil
}

func validateAppDelivery(entry appEntry, uploads []deployment.Upload) error {
	if entry.Delivery == nil {
		if entry.DeliveryInput != nil || entry.Sync != nil && entry.Sync.Recreate == nil || entry.PendingSync != nil && entry.PendingSync.Recreate == nil {
			return ErrCatalog
		}
		return validatePlainRecreation(entry)
	}
	d := *entry.Delivery
	if d.Inventory().Scope() != entry.Inventory.Scope() || d.Principal() != entry.Origin.Session.User {
		return ErrCatalog
	}
	if entry.Sync != nil {
		if entry.Sync.verify(entry.Origin, entry.Inventory.Scope()) != nil {
			return ErrCatalog
		}
		if selected, active := d.Selection(); active && (selected.Operation != entry.Sync.Choice.Operation || selected.Epoch != entry.Sync.Epoch || selected.Plan != entry.Sync.Plan || selected.Intent != entry.Sync.Intent || selected.Artifact != entry.Sync.Artifact) {
			return ErrCatalog
		}
		if e, active := entry.Inventory.Execution(); active && e.Blueprint().IntentDigest() != entry.Sync.Intent {
			return ErrCatalog
		}
		if e, active := entry.Inventory.Execution(); active && verifyLocalBlueprint(entry, entry.Sync.Local, e.Blueprint()) != nil {
			return ErrCatalog
		}
		if summary, exists := entry.Inventory.Operation(entry.Sync.Choice.Operation); exists && summary.Plan != entry.Sync.Plan {
			return ErrCatalog
		}
	}
	if entry.PendingSync != nil {
		if entry.PendingSync.verify(entry.Origin, entry.Inventory.Scope()) != nil {
			return ErrCatalog
		}
		if b, ok := d.TransitionPlan(); ok && verifyLocalBlueprint(entry, entry.PendingSync.Local, b) != nil {
			return ErrCatalog
		}
	}
	if input := entry.DeliveryInput; input != nil {
		ticket, pending := d.FetchTicket()
		commit, err := hex.DecodeString(input.Commit)
		if !pending || ticket != input.Ticket || len(commit) != 20 || err != nil || hex.EncodeToString(commit) != input.Commit {
			return ErrCatalog
		}
		scope := entry.Inventory.Scope()
		index := slices.IndexFunc(uploads, func(u deployment.Upload) bool {
			return u.Tenant == scope.Tenant && u.App == scope.App && u.Deployment == scope.Deployment && u.User == d.Principal() && u.ID == input.Upload
		})
		if index < 0 || uint64(uploads[index].Length) > d.Policy().Limits.Bytes {
			return ErrCatalog
		}
	}
	return nil
}

func (a Apps) deliveryUploadHeld(u deployment.Upload) bool {
	for _, entry := range a.entries {
		if input := entry.DeliveryInput; input != nil && input.Upload == u.ID && entry.Inventory.Scope().Tenant == u.Tenant && entry.Delivery != nil && entry.Delivery.Principal() == u.User {
			return true
		}
	}
	return false
}

func (p Policy) appDeliveryAccess(s state.State, entry appEntry) (access.Catalog, deployment.PlanningContext, error) {
	a, err := p.readOnlyApps(s)
	if err != nil {
		return access.Catalog{}, deployment.PlanningContext{}, err
	}
	return p.appDeliveryAccessFromApps(s, a, entry)
}

// Planning consumes the already checked Apps of this one source operation.
// Current authority is never memoized. Structural consistency is reused only
// for the exact whole committed input checked by readOnlyApps.
func (p Policy) appDeliveryAccessFromApps(s state.State, a Apps, entry appEntry) (access.Catalog, deployment.PlanningContext, error) {
	var ctx deployment.PlanningContext
	c, err := p.Catalog(s)
	if err != nil || entry.Delivery == nil || entry.Down != nil || entry.Delivery.Paused() || !entry.Delivery.Policy().Enabled {
		return c, ctx, ErrCatalog
	}
	scope := entry.Inventory.Scope()
	if c.AuthorizeAccepted(entry.Origin.Session, p.Cluster, entry.Origin.At, scope.Tenant, access.ManageCD, "") != nil {
		return c, ctx, access.ErrDenied
	}
	ctx, err = p.appPlanningFromApps(s, entry.Delivery.Principal(), scope.Tenant, a)
	if err != nil {
		return c, ctx, err
	}
	ctx.Project, ctx.Deployment = scope.App, scope.Deployment
	if begin, err := appOriginBegin(entry.Origin, scope); err == nil {
		ctx.DefaultNode = begin.DefaultNode
	}
	return c, ctx, nil
}

func (p Policy) reduceAppDelivery(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	r, err := p.appDeliveryProgress(s, cmd)
	if err != nil {
		return nil, state.Forbidden
	}
	a, err := p.Apps(s)
	if err != nil {
		return nil, state.Invalid
	}
	key := appKey(r.Tenant, r.App)
	entry, exists := a.entries[key]
	if !exists || entry.Delivery == nil || r.Expected > entry.Delivery.Revision() || r.At < uint64(entry.Origin.At) {
		return nil, state.ConditionFailed
	}
	if r.Target != nil {
		wanted := appSyncTarget(entry)
		switch r.Action {
		case "fetch", "input", "part", "received", "source-error":
			wanted = appDeliverySourceTarget(a, entry)
		}
		if *r.Target != wanted {
			return nil, state.ConditionFailed
		}
	} else if entry.Delivery.Revision() != r.Expected {
		return nil, state.ConditionFailed
	}
	d := *entry.Delivery
	ticket, pending := d.FetchTicket()
	sourceAction := r.Action == "input" || r.Action == "part" || r.Action == "received" || r.Action == "source-error"
	if sourceAction && (!pending || r.Ticket == nil || *r.Ticket != ticket) {
		return nil, state.ConditionFailed
	}
	var c access.Catalog
	var ctx deployment.PlanningContext
	if r.Action != "source-error" && r.Action != "continue" {
		c, ctx, err = p.appDeliveryAccessFromApps(s, a, entry)
		if err != nil {
			return nil, state.Forbidden
		}
	}
	inputIndex := func() int {
		if entry.DeliveryInput == nil {
			return -1
		}
		return slices.IndexFunc(a.uploads, func(u deployment.Upload) bool {
			return u.Tenant == r.Tenant && u.App == r.App && u.User == d.Principal() && u.ID == entry.DeliveryInput.Upload
		})
	}
	switch r.Action {
	case "auto-sync", "replan", "continue":
		work, workErr := p.AppDeliverySyncWork(s, r.Reporter, AppDeliveryWorkRequest{Tenant: r.Tenant, App: r.App, At: r.At, TargetCAS: r.Target != nil})
		if workErr != nil || work.Action != r.Action || r.Action == "auto-sync" && (work.Choice == nil || r.Choice == nil || *work.Choice != *r.Choice) {
			return nil, state.ConditionFailed
		}
		if r.Action == "auto-sync" {
			entry, err = p.acceptCDSync(s, entry, *r.Choice, nil, &r, false)
		}
		if r.Action == "replan" {
			d, err = d.Replan(d.Revision(), c, ctx)
			if err == nil {
				entry.Delivery = &d
			}
		}
		if r.Action == "continue" {
			entry, err = p.continueCDSync(s, entry, r.At)
		}
		if err != nil {
			return nil, state.ConditionFailed
		}
		a.entries[key] = entry
		return p.appsCheckpoint(s, a, r.At)
	case "fetch":
		if entry.DeliveryInput != nil {
			return nil, state.ConditionFailed
		}
		d, _, err = d.Fetch(d.Revision(), c, ctx)
	case "input":
		b := r.Begin
		scope := entry.Inventory.Scope()
		if entry.DeliveryInput != nil || len(a.uploads) >= maxAppUploads || *r.Ticket != r.Input.Ticket || r.Input.Upload != b.ID || b.Tenant != scope.Tenant || b.App != scope.App || b.Deployment != scope.Deployment || uint64(b.Length) > d.Policy().Limits.Bytes {
			return nil, state.ConditionFailed
		}
		u, createErr := deployment.NewUpload(b.Tenant, b.App, b.Deployment, d.Principal(), b.ID, b.Length, b.Digest)
		if createErr != nil || slices.ContainsFunc(a.uploads, func(old deployment.Upload) bool { return uploadKey(old) == uploadKey(u) }) {
			return nil, state.ConditionFailed
		}
		a.uploads = append(slices.Clone(a.uploads), u)
		owned := *r.Input
		entry.DeliveryInput = &owned
	case "part":
		index := inputIndex()
		if index < 0 || r.Part.Tenant != r.Tenant || r.Part.ID != entry.DeliveryInput.Upload {
			return nil, state.ConditionFailed
		}
		a.uploads[index], err = a.uploads[index].Add(r.Part.Index, r.Part.Data)
	case "received":
		index := inputIndex()
		if index < 0 {
			return nil, state.ConditionFailed
		}
		raw, completeErr := a.uploads[index].Complete()
		if completeErr != nil {
			return nil, state.ConditionFailed
		}
		input, restoreErr := deployment.RestoreFetchedDeliveryInput(ticket, entry.DeliveryInput.Commit, d.Policy().Source.Path, raw, int64(d.Policy().Limits.Bytes))
		if restoreErr != nil {
			d, err = d.SourceFailed(d.Revision(), ticket, "invalid")
		} else {
			next, receiveErr := d.Received(d.Revision(), c, ctx, input)
			if receiveErr != nil {
				// A known-invalid input is a source outcome, not a new app
				// operation or an endless loop of denied Received reports.
				d, err = d.SourceFailed(d.Revision(), ticket, "policy")
			} else {
				d = next
			}
		}
		if err == nil {
			a.uploads = slices.Delete(slices.Clone(a.uploads), index, index+1)
			entry.DeliveryInput = nil
		}
	case "source-error":
		d, err = d.SourceFailed(d.Revision(), ticket, r.Error)
		if err == nil {
			if index := inputIndex(); index >= 0 {
				a.uploads = slices.Delete(slices.Clone(a.uploads), index, index+1)
			}
			entry.DeliveryInput = nil
		}
	}
	if err != nil {
		return nil, state.ConditionFailed
	}
	entry.Delivery = &d
	if validateAppDelivery(entry, a.uploads) != nil {
		return nil, state.Invalid
	}
	a.entries[key] = entry
	return p.appsCheckpoint(s, a, r.At)
}

type AppDeliveryRequest struct {
	Tenant, App string
	Ticket      *deployment.DeliveryFetch `json:",omitempty"`
	TargetCAS   bool                      `json:",omitempty"`
}
type AppDeliveryPermit struct {
	Schema                        uint8
	Cluster, Reader               [32]byte
	RootRevision, Revision, Epoch uint64
	Scope                         deployment.AppScope
	Policy                        deployment.DeliveryDeclaration
	Ticket                        *deployment.DeliveryFetch  `json:",omitempty"`
	Input                         *AppDeliveryInput          `json:",omitempty"`
	Upload                        *AppDeliveryUploadProgress `json:",omitempty"`
	Target                        *[32]byte                  `json:",omitempty"`
}
type AppDeliveryUploadProgress struct {
	ID      string
	Length  int
	Digest  [32]byte
	Missing []int
}

// AppDeliveryPermit is a latest-quorum read; the fetch result is rechecked at
// publication. It contains only public source metadata, never Git credentials.
func (p Policy) AppDeliveryPermit(s state.State, caller [32]byte, q AppDeliveryRequest) (AppDeliveryPermit, error) {
	var out AppDeliveryPermit
	members, err := p.Members(s)
	if err != nil || !members.WorkKey(caller) {
		return out, ErrCatalog
	}
	a, err := p.readOnlyApps(s)
	if err != nil {
		return out, err
	}
	entry, exists := a.entries[appKey(q.Tenant, q.App)]
	if !exists {
		return out, ErrCatalog
	}
	if _, _, err = p.appDeliveryAccessFromApps(s, a, entry); err != nil {
		return out, err
	}
	d := *entry.Delivery
	ticket, pending := d.FetchTicket()
	if q.Ticket != nil && (!pending || *q.Ticket != ticket) {
		return out, ErrCatalog
	}
	out = AppDeliveryPermit{Schema: 1, Cluster: p.Cluster, Reader: caller, RootRevision: s.Object(AppsKey).Revision, Revision: d.Revision(), Epoch: s.ModuleEpoch(), Scope: entry.Inventory.Scope(), Policy: d.Policy()}
	if pending {
		out.Ticket = &ticket
	}
	if entry.DeliveryInput != nil {
		owned := *entry.DeliveryInput
		out.Input = &owned
		for _, u := range a.uploads {
			if u.Tenant == q.Tenant && u.App == q.App && u.User == d.Principal() && u.ID == owned.Upload {
				// Return only identity/progress; raw source parts stay in their
				// existing artifact store and cannot become a credential channel.
				out.Upload = &AppDeliveryUploadProgress{ID: u.ID, Length: u.Length, Digest: u.Digest, Missing: u.Missing()}
				break
			}
		}
	}
	if q.TargetCAS {
		target := appDeliverySourceTarget(a, entry)
		out.Target = &target
	}
	return out, nil
}

// DeliverySourceTarget is immutable source metadata, never an authority grant.
// It deliberately ignores Inventory health and partial-upload progress.
func (a Apps) DeliverySourceTarget(tenant, app string) ([32]byte, bool) {
	entry, exists := a.entries[appKey(tenant, app)]
	if !exists || entry.Delivery == nil {
		return [32]byte{}, false
	}
	return appDeliverySourceTarget(a, entry), true
}
func appDeliverySourceTarget(a Apps, entry appEntry) [32]byte {
	d := *entry.Delivery
	var target struct {
		Registration   [32]byte
		Policy         deployment.DeliveryDeclaration
		PolicyRevision uint64
		Paused, Down   bool
		Ticket         *deployment.DeliveryFetch
		Input          *AppDeliveryInput
		Upload         *struct {
			Length int
			Digest [32]byte
		}
	}
	target.Registration = appRegistrationDigest(entry.Origin)
	target.Policy, target.PolicyRevision = d.Policy(), d.PolicyRevision()
	target.Paused, target.Down = d.Paused(), entry.Down != nil
	if ticket, pending := d.FetchTicket(); pending {
		target.Ticket = &ticket
	}
	target.Input = entry.DeliveryInput
	if target.Input != nil {
		for _, u := range a.uploads {
			if u.Tenant == entry.Inventory.Scope().Tenant && u.App == entry.Inventory.Scope().App && u.ID == target.Input.Upload && u.User == d.Principal() {
				target.Upload = &struct {
					Length int
					Digest [32]byte
				}{u.Length, u.Digest}
				break
			}
		}
	}
	raw, _ := json.Marshal(target)
	return sha256.Sum256(append([]byte("mydc-app-delivery-source-target-1\x00"), raw...))
}

func (a Apps) Delivery(tenant, app string) (deployment.Delivery, bool) {
	entry, exists := a.entries[appKey(tenant, app)]
	if !exists || entry.Delivery == nil {
		return deployment.Delivery{}, false
	}
	raw, err := entry.Delivery.Encode()
	if err != nil {
		return deployment.Delivery{}, false
	}
	d, err := deployment.DecodeDelivery(raw)
	return d, err == nil
}
