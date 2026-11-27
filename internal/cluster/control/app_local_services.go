// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"
	"encoding/json"
	"slices"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/secrets"
)

type AppLocalChange struct {
	Tenant, App, Upload  string
	Registration, Digest [32]byte
	Revision             uint64 // exact previous local revision; zero for first addition
	Services             []string
	Target               *[32]byte `json:",omitempty"`
}

// This additional accepted user grant never replaces the original CD actor,
// requester proof key or Secret Group approval. Names are signed metadata and
// are checked against the exact uploaded document before acceptance.
type AppLocalGrant struct {
	Revision uint64
	Digest   [32]byte
	Services []string
	Origin   UserOperation
}

func validLocalNames(names []string) bool {
	if len(names) == 0 || len(names) > 128 || !slices.IsSorted(names) {
		return false
	}
	for i, name := range names {
		if !validID(name) || i > 0 && names[i-1] == name {
			return false
		}
	}
	return true
}

func (q AppLocalChange) valid(action string) bool {
	if !validID(q.Tenant) || !validID(q.App) || q.Registration == ([32]byte{}) || q.Revision == ^uint64(0) || q.Target != nil && *q.Target == ([32]byte{}) {
		return false
	}
	if action == "clear-app-local-services" {
		return q.Upload == "" && q.Digest == ([32]byte{}) && len(q.Services) == 0
	}
	return action == "put-app-local-services" && validID(q.Upload) && q.Digest != ([32]byte{}) && validLocalNames(q.Services)
}

func (g AppLocalGrant) verify(origin UserOperation, scope deployment.AppScope, doc *deployment.LocalServicesDocument) error {
	var q AppLocalChange
	if g.Origin.VerifyOriginal(scope.Cluster) != nil || g.Origin.Change.Action != "put-app-local-services" || canonical(g.Origin.Change.Payload, &q) != nil || !q.valid(g.Origin.Change.Action) || q.Tenant != scope.Tenant || q.App != scope.App || q.Registration != appRegistrationDigest(origin) || g.Revision != q.Revision+1 || g.Digest != q.Digest || !slices.Equal(g.Services, q.Services) || g.Origin.At < origin.At {
		return ErrCatalog
	}
	if doc != nil {
		input, err := deployment.ParseApp(doc.Body)
		if err != nil || doc.Revision != g.Revision || doc.Digest != g.Digest || doc.Actor != g.Origin.Session.User || sha256.Sum256(doc.Body) != doc.Digest {
			return ErrCatalog
		}
		var names []string
		for name := range input.Services {
			names = append(names, name)
		}
		slices.Sort(names)
		if !slices.Equal(names, g.Services) {
			return ErrCatalog
		}
	}
	return nil
}

func ownLocalGrant(g *AppLocalGrant) *AppLocalGrant {
	if g == nil {
		return nil
	}
	raw, _ := json.Marshal(g)
	var owned AppLocalGrant
	_ = json.Unmarshal(raw, &owned)
	return &owned
}

// Compare the frozen document, not the current candidate's mutable grant.
// A queued edit may coexist with an older accepted execution and Bindings.
func verifyLocalBlueprint(entry appEntry, grant *AppLocalGrant, b deployment.Blueprint) error {
	return verifyLocalDocument(entry.Origin, entry.Inventory.Scope(), grant, b)
}

func verifyLocalDocument(origin UserOperation, scope deployment.AppScope, grant *AppLocalGrant, b deployment.Blueprint) error {
	doc := b.OriginalDocument()
	var local *deployment.LocalServicesDocument
	if doc != nil {
		local = doc.LocalServices
	}
	if (local == nil) != (grant == nil) {
		return ErrCatalog
	}
	if local == nil {
		return nil
	}
	return grant.verify(origin, scope, local)
}

func acceptedLocalGrant(entry appEntry) *AppLocalGrant {
	if entry.Sync == nil {
		return nil
	}
	return entry.Sync.Local
}

func (p Policy) authorizeLocalStep(s state.State, c access.Catalog, entry appEntry, e deployment.Execution, key string) error {
	b, grant := e.Blueprint(), acceptedLocalGrant(entry)
	if verifyLocalBlueprint(entry, grant, b) != nil {
		return access.ErrDenied
	}
	if grant == nil {
		return nil
	}
	for _, step := range b.Steps() {
		if step.Key != key {
			continue
		}
		if step.Kind != "task" && step.Kind != "inputs" {
			// Shared plan effects may have several local consumers. Recheck
			// all their authors before creating those effects as well.
			return p.authorizeLocalBlueprint(s, c, entry, grant, b)
		}
		id, err := deployment.ResourceIDFromKey(step.Kind, b.Scope().Tenant, b.Scope().App, key)
		if err != nil {
			return err
		}
		n, err := b.InputMetadata(id, entry.Origin.Session.Key)
		if err != nil {
			return err
		}
		service, _, err := b.TaskInput(id)
		if err != nil {
			return err
		}
		return p.authorizeLocalNeeds(s, c, grant, n, service)
	}
	return access.ErrDenied
}

func appLocalTarget(entry appEntry) [32]byte {
	if entry.Delivery == nil {
		return [32]byte{}
	}
	raw, _ := json.Marshal(struct {
		Intent   [32]byte
		Revision uint64
		Grant    *AppLocalGrant
	}{appSyncTarget(entry), entry.Delivery.LocalRevision(), entry.Local})
	return sha256.Sum256(append([]byte("sfc-app-local-target-1\x00"), raw...))
}

func AppLocalCASAllowed(change Change) bool {
	var q AppLocalChange
	return change.Expected > 0 && canonical(change.Payload, &q) == nil && q.valid(change.Action) && q.Target != nil
}

func validateAppLocal(entry appEntry) error {
	if entry.Delivery == nil {
		if entry.Local != nil || entry.LocalEdit != nil {
			return ErrCatalog
		}
		return nil
	}
	if entry.Delivery.LocalRevision() == 0 {
		if entry.Local != nil || entry.LocalEdit != nil {
			return ErrCatalog
		}
	} else {
		var q AppLocalChange
		edit := entry.LocalEdit
		scope := entry.Inventory.Scope()
		if edit == nil || edit.VerifyOriginal(scope.Cluster) != nil || canonical(edit.Change.Payload, &q) != nil || !q.valid(edit.Change.Action) || q.Tenant != scope.Tenant || q.App != scope.App || q.Registration != appRegistrationDigest(entry.Origin) || q.Revision+1 != entry.Delivery.LocalRevision() || edit.At < entry.Origin.At || (edit.Change.Action == "clear-app-local-services") != (entry.Local == nil) {
			return ErrCatalog
		}
		if entry.Local != nil && (string(OperationBytes(entry.Local.Origin)) != string(OperationBytes(*edit)) || !slices.Equal(entry.Local.Origin.Signature, edit.Signature)) {
			return ErrCatalog
		}
	}
	doc := entry.Delivery.LocalServices()
	if (doc == nil) != (entry.Local == nil) {
		return ErrCatalog
	}
	if doc != nil {
		return entry.Local.verify(entry.Origin, entry.Inventory.Scope(), doc)
	}
	return nil
}

func (p Policy) authorizeLocalNeeds(s state.State, c access.Catalog, grant *AppLocalGrant, n deployment.Needs, service deployment.ComposeService) error {
	if grant == nil || !slices.Contains(grant.Services, n.Use.Service) {
		return nil
	}
	op := grant.Origin
	if c.AuthorizeAccepted(op.Session, p.Cluster, op.At, n.Use.Tenant, access.Deploy, n.Use.Node) != nil {
		return access.ErrDenied
	}
	if _, err := c.CheckImage(op.Session.User, n.Use.Tenant, n.Use.Node, service.Image); err != nil {
		return err
	}
	if len(service.Networks) != 0 && c.AuthorizeAccepted(op.Session, p.Cluster, op.At, n.Use.Tenant, access.ManageNetwork, n.Use.Node) != nil || service.LifecycleProgram != nil && c.AuthorizeAccepted(op.Session, p.Cluster, op.At, n.Use.Tenant, access.ManageServices, n.Use.Node) != nil {
		return access.ErrDenied
	}
	if len(n.Volumes) != 0 {
		if c.AuthorizeAccepted(op.Session, p.Cluster, op.At, n.Use.Tenant, access.ManageVolumes, n.Use.Node) != nil {
			return access.ErrDenied
		}
		registry, err := p.Volumes(s)
		if err != nil {
			return err
		}
		for _, need := range n.Volumes {
			if ref, fixed := n.FixedVolumes[need.Key]; fixed {
				row, exists := registry.entries[need.Key]
				if !exists || !ref.Matches(row.Native) || p.canUseFixedVolume(s, c, op.Session.User, row) != nil {
					return access.ErrDenied
				}
			}
		}
	}
	if !n.HasSources() {
		return nil
	}
	vault, err := p.Vault(s)
	if err != nil {
		return err
	}
	uses := map[string]secrets.Use{}
	for _, source := range n.ApprovalSources() {
		use, present := uses[source.Realm]
		if !present {
			use = n.Use
			use.User, use.RequesterKey, use.Sources = op.Session.User, op.Session.Key, nil
		}
		use.Sources = append(use.Sources, source.Object)
		uses[source.Realm] = use
	}
	for realm, use := range uses {
		tree, exists := vault.Trees[realm]
		if !exists {
			return access.ErrDenied
		}
		// Check all selected source/ancestor ACLs as the actual local author.
		// This neither issues a Group approval nor borrows the CD actor's ACL.
		if _, err := tree.Plan(c, []secrets.Use{use}); err != nil {
			return err
		}
	}
	return nil
}

func (p Policy) authorizeLocalBlueprint(s state.State, c access.Catalog, entry appEntry, grant *AppLocalGrant, b deployment.Blueprint) error {
	if verifyLocalBlueprint(entry, grant, b) != nil {
		return ErrCatalog
	}
	if grant == nil {
		return nil
	}
	for _, step := range b.Steps() {
		if step.Kind != "task" {
			continue
		}
		id, err := deployment.ResourceIDFromKey("task", b.Scope().Tenant, b.Scope().App, step.Key)
		if err != nil {
			return err
		}
		n, err := b.InputMetadata(id, entry.Origin.Session.Key)
		if err != nil {
			return err
		}
		service, _, err := b.TaskInput(id)
		if err != nil || p.authorizeLocalNeeds(s, c, grant, n, service) != nil {
			return access.ErrDenied
		}
	}
	return nil
}

func (p Policy) reduceAppLocal(s state.State, a Apps, op UserOperation) (map[string][]byte, state.Code) {
	var q AppLocalChange
	if canonical(op.Change.Payload, &q) != nil || !q.valid(op.Change.Action) {
		return nil, state.Invalid
	}
	key := appKey(q.Tenant, q.App)
	entry, exists := a.entries[key]
	if !exists || entry.Delivery == nil || q.Registration != appRegistrationDigest(entry.Origin) || q.Revision != entry.Delivery.LocalRevision() || entry.Down != nil || entry.PendingSync != nil || op.Change.Expected > entry.Delivery.Revision() || q.Target == nil && op.Change.Expected != entry.Delivery.Revision() || q.Target != nil && *q.Target != appLocalTarget(entry) {
		return nil, state.ConditionFailed
	}
	c, ctx, err := p.appDeliveryAccess(s, entry)
	if err != nil {
		return nil, state.Forbidden
	}
	volumes, err := p.Volumes(s)
	if err != nil || volumes.appMovePending(q.Tenant, q.App) {
		return nil, state.ConditionFailed
	}
	var body []byte
	uploadAt := -1
	if op.Change.Action == "put-app-local-services" {
		uploadAt = slices.IndexFunc(a.uploads, func(u deployment.Upload) bool {
			return u.Tenant == q.Tenant && u.App == q.App && u.Deployment == entry.Inventory.Scope().Deployment && u.User == op.Session.User && u.ID == q.Upload && u.Digest == q.Digest
		})
		if uploadAt < 0 || a.deliveryUploadHeld(a.uploads[uploadAt]) || p.moveUploadHeld(s, a.uploads[uploadAt]) {
			return nil, state.ConditionFailed
		}
		body, err = a.uploads[uploadAt].Complete()
		if err != nil {
			return nil, state.ConditionFailed
		}
		input, parseErr := deployment.ParseApp(body)
		var names []string
		for name := range input.Services {
			names = append(names, name)
		}
		slices.Sort(names)
		if parseErr != nil || !slices.Equal(names, q.Services) {
			return nil, state.Invalid
		}
	}
	d, err := entry.Delivery.PutLocalServices(entry.Delivery.Revision(), q.Revision, c, ctx, op.Session.User, body)
	if err != nil {
		return nil, state.ConditionFailed
	}
	if d.LocalRevision() != entry.Delivery.LocalRevision() {
		entry.LocalEdit = &op
		entry.Local = nil
		if local := d.LocalServices(); local != nil {
			entry.Local = &AppLocalGrant{Revision: local.Revision, Digest: local.Digest, Services: slices.Clone(q.Services), Origin: op}
			if entry.Local.verify(entry.Origin, entry.Inventory.Scope(), local) != nil {
				return nil, state.Invalid
			}
		}
	}
	entry.Delivery = &d
	b, ok := d.CandidateBlueprint()
	if !ok || p.authorizeCDSelection(s, c, entry, b, nil, entry.Local) != nil {
		return nil, state.Forbidden
	}
	if uploadAt >= 0 {
		a.uploads = slices.Delete(slices.Clone(a.uploads), uploadAt, uploadAt+1)
	}
	a.entries[key] = entry
	return p.appsCheckpoint(s, a, uint64(op.At))
}
