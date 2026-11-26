// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strconv"
	"strings"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/secrets"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

// Selection carries no inventory, owner set or native path. The FSM derives
// those from the same immutable candidate that closes new tenant admission.
type TenantRetirementSelection struct{ Tenant, Operation string }

type TenantRetirementStatus struct {
	Schema                                                uint8
	Tenant                                                access.Tenant
	Remaining                                             []access.RetirementTarget
	Index, RootRevision                                   uint64
	TargetCount, OwnerCount, ClosedOwners, RemainingCount int
	Next                                                  string
}

// tenantInventory is intentionally not a user-filtered listing. Terminal
// histories remain in their original catalogs. Kept Volume/backup bytes remain
// blockers until their existing explicit delete/unregister contracts settle.
func (p Policy) tenantInventory(s state.State, tenant string, freeze bool) ([]access.RetirementTarget, error) {
	builds, buildErr := p.ImageBuilds(s)
	if buildErr != nil {
		return nil, buildErr
	}
	for _, row := range builds.CachePrunes {
		q, err := row.Change()
		if err != nil || q.Tenant == tenant && row.Pending() {
			return nil, ErrCatalog
		}
	}
	for _, job := range builds.Jobs {
		if job.Run.Spec.Tenant == tenant && !job.Deleted {
			return nil, ErrCatalog
		}
	}
	// Until the build owner has settled its contexts/artifacts, an omitted
	// target must not turn tenant-wide deletion into a false empty census.
	for _, r := range builds.Policies {
		if r.Spec.Tenant == tenant && !r.Deleted {
			return nil, ErrCatalog
		}
	}
	for _, r := range builds.Contexts {
		if r.Spec.Tenant == tenant && !r.Deleted {
			return nil, ErrCatalog
		}
	}
	for _, r := range builds.Uploads {
		if r.Scope.Tenant == tenant && r.Reclaimed == nil {
			return nil, ErrCatalog
		}
	}
	maintenance, err := p.RegistryMaintenanceJobs(s)
	if err != nil {
		return nil, err
	}
	for _, row := range maintenance.Records {
		if row.Pending() && row.Change.Tenant == tenant {
			return nil, ErrCatalog
		}
	}
	users, err := p.Catalog(s)
	if err != nil {
		return nil, err
	}
	selected, exists := users.Tenant(tenant)
	if !exists {
		return nil, ErrCatalog
	}
	directory, err := p.Members(s)
	if err != nil {
		return nil, err
	}
	anchor := directory.Genesis
	for _, entry := range directory.Entries {
		key, parseErr := identity.ParseKey(entry.Peer.Key)
		if parseErr != nil {
			return nil, parseErr
		}
		if directory.MemberKey(key) {
			anchor = entry.Peer
			break
		}
	}
	anchorKey, err := identity.ParseKey(anchor.Key)
	if err != nil {
		return nil, err
	}
	var targets []access.RetirementTarget
	seen := map[string]bool{}
	add := func(kind, key, node string, owner [32]byte, generation uint64, retained bool) {
		if node == "" {
			node, owner = anchor.ID, anchorKey
		}
		hash := sha256.Sum256([]byte(kind + "\x00" + key + "\x00" + node + "\x00" + hex.EncodeToString(owner[:]) + "\x00" + strconv.FormatUint(max(1, generation), 10)))
		id := "r" + hex.EncodeToString(hash[:24])
		identity := kind + "/" + id
		if seen[identity] {
			return
		}
		seen[identity] = true
		targets = append(targets, access.RetirementTarget{Tenant: tenant, Kind: kind, ID: id, Node: node, Owner: owner, Generation: max(1, generation), Retain: retained, Key: key})
	}
	nodeFor := func(owner [32]byte) (string, error) {
		for _, entry := range directory.Entries {
			key, e := identity.ParseKey(entry.Peer.Key)
			if e != nil {
				return "", e
			}
			if key == owner {
				return entry.Peer.ID, nil
			}
		}
		return "", ErrCatalog
	}
	addOwner := func(kind, key string, owner [32]byte, generation uint64, retained bool) error {
		if owner == ([32]byte{}) {
			add(kind, key, "", owner, generation, retained)
			return nil
		}
		node, e := nodeFor(owner)
		if e != nil {
			return e
		}
		add(kind, key, node, owner, generation, retained)
		return nil
	}
	if freeze {
		// The control anchor and every assigned node must inspect local state,
		// including an orphan not visible in the shared resource inventory.
		add("owner", "", anchor.ID, anchorKey, 1, false)
		for _, node := range selected.AllowedNodes {
			entry, ok := directory.Entry(node)
			key, e := identity.ParseKey(entry.Peer.Key)
			if !ok || e != nil {
				return nil, ErrCatalog
			}
			// A removed idle member has already supplied the existing full
			// node closure. Actual remaining resources still add its original
			// owner below; a stale allow-list alone is not new native work.
			if directory.MemberKey(key) {
				add("owner", "", node, key, 1, false)
			}
		}
		// Retained build history can name a cache/artifact owner removed from
		// the tenant's current allow-list. Active original members must still
		// inspect their native state; a certified removed node is already closed.
		for _, job := range builds.Jobs {
			root := job.Run.Spec.Scope.Root
			if job.Run.Spec.Tenant == tenant && directory.MemberKey(root.Key) {
				add("owner", "", root.Node, root.Key, 1, false)
			}
		}
		for _, context := range builds.Contexts {
			root := context.Spec.Root
			if context.Spec.Tenant == tenant && directory.MemberKey(root.Key) {
				add("owner", "", root.Node, root.Key, 1, false)
			}
		}
	}
	apps, err := p.Apps(s)
	if err != nil {
		return nil, err
	}
	for _, entry := range apps.entries {
		scope := entry.Inventory.Scope()
		if scope.Tenant != tenant {
			continue
		}
		if pendingTaskRestarts(entry) || !entry.Inventory.Quiescent() || entry.PendingSync != nil || entry.Delivery != nil && !entry.Delivery.Quiescent() {
			add("app-operation", scope.App, "", [32]byte{}, entry.Inventory.Revision(), false)
		}
		for _, row := range entry.TaskRestarts {
			if row.Control == nil || !row.Control.Terminal() {
				initial, err := row.InitialControl()
				if err != nil {
					return nil, err
				}
				if err = addOwner("app-operation", scope.App+"/restart/"+initial.RunID, row.Plan.Container.Owner, row.Plan.Container.Generation, false); err != nil {
					return nil, err
				}
			}
		}
		for _, claim := range entry.Inventory.Claims() {
			if claim.Removed || claim.Retained {
				continue
			}
			if err := addOwner(claim.Step.Kind, claim.Step.Key, claim.Step.Owner, s.Object(claim.Step.Key).Generation, false); err != nil {
				return nil, err
			}
		}
	}
	for _, upload := range apps.uploads {
		if upload.Tenant != tenant {
			continue
		}
		if len(upload.Missing()) != 0 {
			add("app-upload", uploadKey(upload), "", [32]byte{}, upload.Revision, false)
		}
	}
	for _, binding := range apps.bindings.Live() {
		needs := binding.Needs()
		digest := binding.Digest()
		if needs.Use.Tenant == tenant {
			if err := addOwner("binding", "binding/"+hex.EncodeToString(digest[:]), needs.Use.NodeKey, needs.Generation, false); err != nil {
				return nil, err
			}
		}
	}
	resources, err := p.Resources(s)
	if err != nil {
		return nil, err
	}
	for _, network := range resources.Networks.AllNetworks() {
		if network.Tenant == tenant {
			add("network", network.ID, network.Node, network.Owner, network.Generation, false)
		}
	}
	for _, route := range resources.Networks.AllRoutes() {
		if route.Source.Tenant != tenant && route.Destination.Tenant != tenant {
			continue
		}
		for _, side := range []struct {
			Node  string
			Owner [32]byte
		}{{route.Source.Node, route.Source.Owner}, {route.Destination.Node, route.Destination.Owner}} {
			add("route", route.Source.Tenant+"/"+route.ID, side.Node, side.Owner, route.Generation, false)
		}
	}
	for _, reservation := range resources.Quotas.Reservations() {
		if reservation.Tenant == tenant {
			add("reservation", reservation.Key, reservation.Node, reservation.Owner, reservation.Generation, false)
		}
	}
	projection, err := p.ProjectResources(s)
	if err != nil {
		return nil, err
	}
	for key, goal := range projection.Goals {
		if goal.Goal.Tenant == tenant && goal.Goal.Kind != "volume" && s.Object(key).Present {
			add(goal.Goal.Kind, key, goal.Goal.Node, goal.Goal.Owner, s.Object(key).Generation, false)
		}
	}
	for key, source := range projection.ManagedSources {
		if source.Network.Tenant == tenant && s.Object(key).Present && source.Closed == nil {
			kind := "bridge"
			if source.Tunnel != nil {
				kind = "tunnel"
			}
			add(kind, key, source.Network.Node, source.Network.Owner, s.Object(key).Generation, false)
		}
	}
	dns, err := p.ManagedDNS(s)
	if err != nil {
		return nil, err
	}
	for key, row := range dns {
		if row.Definition.Tenant == tenant && row.Definition.Policy.Enabled {
			add("dns-policy", key, "", [32]byte{}, s.Object(key).Generation, false)
		}
	}
	if apps.network != nil {
		for _, group := range apps.network.Groups {
			if group.Tenant == tenant {
				for _, row := range group.Owners {
					ref, ok := apps.network.Authority.ReferenceConsumer(row.Reference)
					if !ok {
						return nil, ErrCatalog
					}
					add("dns", row.Config.ID, ref.Local.Node, ref.Local.Owner, row.Config.Source, false)
				}
			}
		}
		for _, ref := range apps.network.Authority.ReferenceConsumers() {
			relevant := ref.Local.Tenant == tenant
			for _, member := range ref.Members {
				relevant = relevant || member.Source.Tenant == tenant
			}
			if relevant && ref.Closed == nil {
				add("network-reference", ref.Scope, ref.Local.Node, ref.Local.Owner, ref.Generation, false)
			}
		}
	}
	volumeCatalog, err := p.Volumes(s)
	if err != nil {
		return nil, err
	}
	for _, row := range volumeCatalog.entries {
		if row.State.Scope().Tenant != tenant {
			continue
		}
		if !row.State.Deleted() {
			add("volume", volumes.NativeKey(row.Native.Spec), row.Native.Spec.Node, row.Native.Spec.NodeKey, row.Native.Generation, true)
		}
		for _, retained := range row.State.Retained() {
			move, exists := volumeCatalog.moves[moveKey(VolumeMoveSelection{Scope: row.State.Scope(), ID: retained.Move})]
			if !exists || move.Source.Owner != retained.Owner {
				return nil, ErrCatalog
			}
			add("volume", volumes.NativeKey(move.Source.Spec), move.Source.Spec.Node, move.Source.Spec.NodeKey, move.Source.Generation, true)
		}
	}
	for _, job := range volumeCatalog.creations {
		if job.Spec.Scope.Tenant == tenant && job.Phase != "Ready" && job.Phase != "Cancelled" && job.Phase != "Unregistered" {
			add("volume-create", volumes.NativeKey(job.Spec), job.Spec.Node, job.Spec.NodeKey, job.Revision, false)
		}
	}
	for _, job := range volumeCatalog.moves {
		if job.Binding.Scope.Tenant != tenant {
			continue
		}
		entry, ok := volumeCatalog.entries[volumeKey(job.Binding.Scope)]
		if !ok {
			return nil, ErrCatalog
		}
		move, ok := entry.State.Move(job.Binding.ID)
		if !ok {
			return nil, ErrCatalog
		}
		if move.Phase != volumes.Completed && move.Phase != volumes.Cancelled {
			add("volume", volumes.NativeKey(job.Source.Spec), job.Source.Spec.Node, job.Source.Spec.NodeKey, job.Source.Generation, true)
			add("volume", volumes.NativeKey(job.Target), job.Target.Node, job.Target.NodeKey, job.Target.Scope.Generation, true)
		}
	}
	for _, job := range volumeCatalog.backups {
		if job.Binding.Scope.Tenant == tenant && (backupPending(job.Phase) || job.Phase == "Ready" || job.Phase == "Deleting") {
			add("backup", backupKey(job.Binding.Scope, job.Binding.ID), job.Binding.Source.Spec.Node, job.Binding.Source.Spec.NodeKey, job.Revision, true)
		}
	}
	for _, job := range volumeCatalog.restores {
		if job.Binding.Target.Scope.Tenant == tenant && restorePending(job.Phase) {
			add("restore", volumes.NativeKey(job.Binding.Target), job.Binding.Target.Node, job.Binding.Target.NodeKey, job.Revision, false)
		}
	}
	registries, err := p.Registries(s)
	if err != nil {
		return nil, err
	}
	for _, row := range registries.Entries() {
		if row.Spec.Tenant == tenant && (!row.Deleted || row.Active != nil) {
			add("registry", row.Spec.ID, row.Spec.Node, row.DataOwner, row.Revision, false)
		}
	}
	external, err := p.ExternalRegistries(s)
	if err != nil {
		return nil, err
	}
	for _, row := range external {
		if row.Spec.Tenant == tenant && (!row.Deleted || row.Reader != nil) {
			add("external-registry", row.Spec.ID, "", [32]byte{}, row.Revision, false)
			if r := row.Reader; r != nil {
				add("external-registry-reader", row.Spec.ID, r.Node, r.Owner, r.Generation, false)
			}
		}
	}
	scripts, err := p.Lifecycles(s)
	if err != nil {
		return nil, err
	}
	for _, row := range scripts.Records(tenant) {
		for _, version := range row.Versions {
			if !version.Deleted {
				add("script", row.Name, "", [32]byte{}, row.Revision, false)
				if freeze {
					key := "checker-source/" + hex.EncodeToString(version.Source.Digest[:])
					if err := addOwner("owner", key, version.Source.Owner, version.Revision, false); err != nil {
						return nil, err
					}
				}
			}
		}
	}
	for _, use := range scripts.Uses() {
		if use.Tenant == tenant {
			add("script-use", use.ID, use.Node, use.Owner, use.PolicyRevision, false)
			if freeze {
				for _, source := range use.Sources {
					if err := addOwner("owner", "checker-source/"+hex.EncodeToString(source.Digest[:]), source.Owner, use.PolicyRevision, false); err != nil {
						return nil, err
					}
				}
			}
		}
	}
	for _, job := range scripts.BuildJobs() {
		if job.Intent.Tenant == tenant && job.Phase != "closed" {
			add("script-build", job.Intent.ID, job.Intent.Node, job.Intent.Owner, job.Revision, false)
		}
	}
	vault, err := p.Vault(s)
	if err != nil {
		return nil, err
	}
	if tree, ok := vault.Trees[tenant]; ok {
		for _, object := range tree.Objects() {
			if object.Parent != "" && object.Status != secrets.Retired {
				add("secret", object.ID, "", [32]byte{}, object.Revision, false)
				if freeze && object.Reference.Profile != "" {
					profile, ok := tree.WriteProfile(object.Reference.Profile)
					if !ok {
						return nil, ErrCatalog
					}
					add("owner", "secret-provider/"+profile.ID, profile.Node, profile.Key, profile.Revision, false)
				}
			}
		}
		for _, write := range tree.Writes() {
			if write.Status() != "Published" && write.Status() != "Abandoned" {
				add("secret-write", write.Request.ID, write.Writer.Node, write.Writer.Key, write.Generation, false)
			}
		}
		if !tree.Quiescent() {
			add("vault-operation", tenant, "", [32]byte{}, tree.Revision(), false)
		}
	}
	slices.SortFunc(targets, func(a, b access.RetirementTarget) int { return strings.Compare(a.Kind+"/"+a.ID, b.Kind+"/"+b.ID) })
	return targets, nil
}

// Owner reports carry their own exact core signature plus current module CAS.
// The request ID is derived from these original bytes for replay preservation.
type TenantRetirementReport struct {
	Schema              uint8
	Epoch, RootRevision uint64
	Proof               access.TenantReport
}

func (r TenantRetirementReport) Command() (state.Command, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return state.Command{}, err
	}
	cmd := state.Command{Kind: state.ModuleReport, Actor: "node/" + hex.EncodeToString(r.Proof.Owner[:]), Epoch: r.Epoch, Key: CatalogKey, Expected: r.RootRevision, Value: string(raw)}
	cmd.RequestID = state.ReportRequestID(cmd)
	_, err = state.EncodeCommand(cmd)
	return cmd, err
}
func (p Policy) ResolveTenantRetirementReport(s state.State, caller [32]byte, raw []byte) (state.Command, error) {
	current, err := p.Current(s)
	if err != nil {
		return state.Command{}, err
	}
	p = current
	var report TenantRetirementReport
	if canonical(raw, &report) != nil || report.Schema != 1 || report.Proof.Owner != caller || report.Proof.Cluster != p.Cluster || !ed25519.Verify(caller[:], access.TenantReportBytes(report.Proof), report.Proof.Signature) {
		return state.Command{}, access.ErrDenied
	}
	cmd, err := report.Command()
	if err != nil {
		return cmd, err
	}
	if _, found := s.LookupResult(cmd); found {
		return cmd, nil
	}
	users, err := p.Catalog(s)
	if err != nil {
		return cmd, err
	}
	work, err := p.TenantRetirementWork(s, caller, report.Proof.Tenant)
	if err != nil || work.Remaining != 0 || work.Complete || report.Proof.Sequence != work.Sequence {
		return cmd, access.ErrDenied
	}
	_, err = users.ObserveTenantRetirement(report.Proof)
	return cmd, err
}
func (p Policy) reduceTenantRetirementReport(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	current, err := p.Current(s)
	if err != nil {
		return nil, state.Invalid
	}
	p = current
	var report TenantRetirementReport
	if canonical([]byte(cmd.Value), &report) != nil || cmd.Kind != state.ModuleReport || report.Epoch != s.ModuleEpoch() {
		return nil, state.Forbidden
	}
	want, err := p.ResolveTenantRetirementReport(s, report.Proof.Owner, []byte(cmd.Value))
	if err != nil || want != cmd {
		return nil, state.Forbidden
	}
	users, err := p.Catalog(s)
	if err != nil {
		return nil, state.Invalid
	}
	users, err = users.ObserveTenantRetirement(report.Proof)
	if err != nil {
		return nil, state.ConditionFailed
	}
	return p.checkpoint(s, users)
}

func (p Policy) TenantRetirementStatus(s state.State, tenant, after string) (TenantRetirementStatus, error) {
	users, err := p.Catalog(s)
	if err != nil {
		return TenantRetirementStatus{}, err
	}
	t, ok := users.Tenant(tenant)
	if !ok {
		return TenantRetirementStatus{}, ErrCatalog
	}
	remaining, err := p.tenantInventory(s, tenant, false)
	if err != nil {
		return TenantRetirementStatus{}, err
	}
	status := TenantRetirementStatus{Schema: 1, Tenant: t, Index: s.Index(), RootRevision: s.Object(CatalogKey).Revision, RemainingCount: len(remaining)}
	// The complete frozen inventory stays in the checkpoint, not each reply.
	if t.Retirement != nil {
		status.TargetCount = len(t.Retirement.Targets)
		status.OwnerCount = len(t.Retirement.Owners)
		original := *t.Retirement
		status.Tenant.Retirement.Targets = nil
		status.Tenant.Retirement.Owners = nil
		for _, owner := range original.Owners {
			if owner.Report != nil && owner.Report.Complete() {
				status.ClosedOwners++
			}
		}
	}
	for _, target := range remaining {
		cursor := target.Kind + "/" + target.ID
		if cursor <= after {
			continue
		}
		if len(status.Remaining) == 8 {
			status.Next = status.Remaining[7].Kind + "/" + status.Remaining[7].ID
			break
		}
		status.Remaining = append(status.Remaining, target)
	}
	return status, nil
}

type TenantRetirementWork struct {
	Schema                                                uint8
	Cluster, Owner                                        [32]byte
	Tenant, Operation                                     string
	InventoryHash, OwnersHash                             [32]byte
	StartedRevision, Sequence, Index, Epoch, RootRevision uint64
	Remaining                                             int
	Complete                                              bool
}

func (p Policy) TenantRetirementWork(s state.State, owner [32]byte, tenant string) (TenantRetirementWork, error) {
	users, err := p.Catalog(s)
	if err != nil {
		return TenantRetirementWork{}, err
	}
	t, ok := users.Tenant(tenant)
	if !ok || t.Phase != access.TenantRetiring || t.Retirement == nil {
		return TenantRetirementWork{}, access.ErrDenied
	}
	retirement := t.Retirement
	for _, original := range retirement.Owners {
		if original.Key != owner {
			continue
		}
		remaining, err := p.tenantInventory(s, tenant, false)
		if err != nil {
			return TenantRetirementWork{}, err
		}
		sequence := uint64(1)
		if original.Report != nil {
			sequence = original.Report.Sequence + 1
		}
		if sequence == 0 {
			return TenantRetirementWork{}, ErrCatalog
		}
		return TenantRetirementWork{Schema: 1, Cluster: p.Cluster, Owner: owner, Tenant: tenant, Operation: retirement.Operation, InventoryHash: retirement.InventoryHash, OwnersHash: retirement.OwnersHash, StartedRevision: retirement.StartedRevision, Sequence: sequence, Index: s.Index(), Epoch: s.ModuleEpoch(), RootRevision: s.Object(CatalogKey).Revision, Remaining: len(remaining), Complete: original.Report != nil && original.Report.Complete()}, nil
	}
	return TenantRetirementWork{}, access.ErrDenied
}

func (p Policy) validateTenantRetirements(s state.State) error {
	users, err := p.Catalog(s)
	if err != nil {
		return err
	}
	for _, tenant := range users.Tenants() {
		if tenant.Phase == access.TenantActive {
			continue
		}
		if err := p.tenantRetirementEvidence(s, tenant); err != nil {
			return err
		}
		if tenant.Phase != access.TenantDeleted {
			continue
		}
		remaining, err := p.tenantInventory(s, tenant.ID, false)
		if err != nil {
			return err
		}
		if len(remaining) != 0 {
			return ErrCatalog
		}
	}
	return nil
}

func tenantRetirementEvidenceKey(tenant, operation string) string {
	return "control/tenant-retirement/" + tenant + "/" + operation
}

type tenantRetirementEvidence struct {
	Schema            uint8
	Tenant, Operation string
	StartedRevision   uint64
	Targets           []access.RetirementTarget
}

func (p Policy) tenantRetirementEvidence(s state.State, t access.Tenant) error {
	if t.Retirement == nil {
		return ErrCatalog
	}
	r := t.Retirement
	raw, revision, err := readCheckpoint(s, tenantRetirementEvidenceKey(t.ID, r.Operation), p.Cluster, p.TrustRoot)
	var evidence tenantRetirementEvidence
	if err != nil || revision != 1 || canonical(raw, &evidence) != nil || evidence.Schema != 1 || evidence.Tenant != t.ID || evidence.Operation != r.Operation || evidence.StartedRevision != r.StartedRevision || !r.MatchesInventory(t.ID, evidence.Targets) {
		return ErrCatalog
	}
	return nil
}
