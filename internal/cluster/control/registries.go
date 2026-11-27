// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	registry "github.com/jay94ks/seafield/internal/registry"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

const RegistriesKey = "control/registries"
const maxRegistries = 128

type RegistrySelection struct{ Tenant, ID string }
type RegistryPut struct{ Spec registry.Specification }
type RegistryObservation struct {
	At                int64
	Boot, Certificate [32]byte
}
type RegistryRun struct {
	Generation, SpecRevision uint64
	Spec                     registry.Specification
	Owner                    [32]byte
	Principal                string
	Definition, Origin       UserOperation
	Consumer                 volumes.Consumer
	Budget                   tenancy.Reservation
	Draining                 bool
	Ready                    *RegistryObservation `json:",omitempty"`
}
type RegistryClosure struct {
	Run    RegistryRun
	Gone   volumes.Gone
	Budget tenancy.ReservationClosure
}
type RegistryEntry struct {
	Spec                        registry.Specification
	Revision, Generation        uint64
	DataOwner                   [32]byte
	Initial, Definition, Origin UserOperation
	Deleted                     bool
	Active                      *RegistryRun     `json:",omitempty"`
	Closed                      *RegistryClosure `json:",omitempty"`
}
type Registries struct {
	Revision uint64
	entries  map[string]RegistryEntry
}
type registryCheckpoint struct {
	Schema   uint8
	Cluster  [32]byte
	Revision uint64
	Entries  []RegistryEntry
}

func ownRegistry(r RegistryEntry) RegistryEntry {
	raw, _ := json.Marshal(r)
	var owned RegistryEntry
	_ = json.Unmarshal(raw, &owned)
	return owned
}
func (r Registries) Entry(tenant, id string) (RegistryEntry, bool) {
	e, ok := r.entries[tenant+"/"+id]
	return ownRegistry(e), ok
}
func (r Registries) Entries() []RegistryEntry {
	keys := make([]string, 0, len(r.entries))
	for k := range r.entries {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	rows := make([]RegistryEntry, 0, len(keys))
	for _, key := range keys {
		rows = append(rows, ownRegistry(r.entries[key]))
	}
	return rows
}
func registryConsumer(cluster [32]byte, tenant, id string) string {
	raw, _ := json.Marshal(struct {
		Cluster    [32]byte
		Tenant, ID string
	}{cluster, tenant, id})
	hash := sha256.Sum256(append([]byte("sfc-registry-volume-consumer-1\x00"), raw...))
	return "registry-" + hex.EncodeToString(hash[:24])
}

func (p Policy) Registries(s state.State) (Registries, error) {
	result := Registries{entries: map[string]RegistryEntry{}}

	raw, revision, err := readCheckpoint(s, RegistriesKey, p.Cluster, p.TrustRoot)
	if err != nil {
		return result, err
	}
	if raw == nil {
		return result, nil
	}
	var disk registryCheckpoint
	if canonical(raw, &disk) != nil || disk.Schema != 1 || disk.Cluster != p.Cluster || disk.Revision != revision || revision == 0 || len(disk.Entries) > maxRegistries {
		return result, ErrCatalog
	}
	users, err := p.Catalog(s)
	if err != nil {
		return result, err
	}
	members, err := p.Members(s)
	if err != nil {
		return result, err
	}
	last := ""
	for _, entry := range disk.Entries {
		key := entry.Spec.Key()
		if key <= last || entry.Spec.Validate(p.Cluster) != nil || entry.Revision == 0 || entry.DataOwner == ([32]byte{}) || entry.Initial.VerifyOriginal(p.Cluster) != nil || !p.registryDefinition(entry.Spec, entry.Revision, entry.Definition, entry.Origin) {
			return result, ErrCatalog
		}
		var initial RegistryPut
		if entry.Initial.Change.Action != "put-registry" || entry.Initial.Change.Expected != 0 || canonical(entry.Initial.Change.Payload, &initial) != nil || initial.Spec.Key() != key || initial.Spec.Volume != entry.Spec.Volume {
			return result, ErrCatalog
		}
		historical, exists := members.Entry(initial.Spec.Node)
		if !exists || historical.Peer.Key != hex.EncodeToString(entry.DataOwner[:]) {
			return result, ErrCatalog
		}
		if _, ok := users.Tenant(entry.Spec.Tenant); !ok {
			return result, ErrCatalog
		}
		if entry.Deleted && (entry.Spec.Enabled || entry.Active != nil) {
			return result, ErrCatalog
		}
		if run := entry.Active; run != nil {
			if run.Generation != entry.Generation || !p.validRegistryRun(*run, entry) {
				return result, ErrCatalog
			}
		}
		if closed := entry.Closed; closed != nil {
			run := closed.Run
			proof := closed.Budget
			if !p.validRegistryRun(run, entry) || run.Generation > entry.Generation || entry.Active != nil && run.Generation >= entry.Active.Generation || !run.Draining || closed.Gone.Scope != run.Spec.Volume || closed.Gone.Consumer != run.Consumer || !closed.Gone.Stopped || !closed.Gone.MountsGone || !ed25519.Verify(run.Owner[:], volumes.GoneBytes(closed.Gone), closed.Gone.Signature) {
				return result, ErrCatalog
			}
			if proof.Schema != 1 || proof.Cluster != p.Cluster || proof.Owner != run.Owner || proof.Node != run.Spec.Node || proof.Key != run.Budget.Key || proof.Generation != run.Budget.Generation || proof.DrainRevision != run.Budget.Revision || !proof.NativeGone || proof.PendingNative != 0 || proof.PendingRefs != 0 || proof.PendingWriters != 0 || !ed25519.Verify(run.Owner[:], tenancy.ReservationClosureBytes(proof), proof.Signature) {
				return result, ErrCatalog
			}
		}
		if entry.Active == nil && entry.Generation > 0 && (entry.Closed == nil || entry.Closed.Run.Generation != entry.Generation) {
			return result, ErrCatalog
		}
		result.entries[key] = entry
		last = key
	}
	result.Revision = revision
	if registryEndpoints(result) != nil {
		return result, ErrCatalog
	}
	return result, nil
}

// Both a live run and its closed receipt retain this same accepted identity.
func (p Policy) validRegistryRun(run RegistryRun, entry RegistryEntry) bool {
	if run.Generation == 0 || run.SpecRevision == 0 || run.SpecRevision > entry.Revision || run.Spec.Validate(p.Cluster) != nil || run.Spec.Key() != entry.Spec.Key() || run.Spec.Volume != entry.Spec.Volume || !run.Spec.Enabled || run.Owner == ([32]byte{}) {
		return false
	}
	if !p.registryDefinition(run.Spec, run.SpecRevision, run.Definition, run.Origin) || run.Principal != run.Origin.Session.User {
		return false
	}
	consumer := run.Consumer
	if consumer.ID != registryConsumer(p.Cluster, run.Spec.Tenant, run.Spec.ID) || consumer.Generation != run.Generation || !consumer.Writable || consumer.Owner.Key != run.Owner || consumer.Owner.Node != run.Spec.Node || consumer.Owner.Native == "" || consumer.OwnerRevision == 0 || consumer.Lease.Generation != run.Spec.Volume.Generation || consumer.Lease.Token == 0 {
		return false
	}
	budget := run.Budget
	if !budget.ManagedRegistry || budget.Key != run.Spec.BudgetKey() || budget.Need != run.Spec.Budget || budget.Tenant != run.Spec.Tenant || budget.Node != run.Spec.Node || budget.Owner != run.Owner || budget.Draining != run.Draining || budget.Generation == 0 || budget.Revision < budget.Generation {
		return false
	}
	return run.Ready == nil || run.Ready.At > 0 && run.Ready.Boot != ([32]byte{}) && run.Ready.Certificate != ([32]byte{})
}

// The last definition and the accepted start grant remain distinct. An enabled
// bit can change through start/stop; no other field can be rewritten without
// retaining the original signed put. Old runs keep their own accepted pair.
func (p Policy) registryDefinition(spec registry.Specification, revision uint64, definition, origin UserOperation) bool {
	if revision == 0 || definition.VerifyOriginal(p.Cluster) != nil || origin.VerifyOriginal(p.Cluster) != nil || definition.Change.Action != "put-registry" || definition.Change.Expected >= revision || origin.Change.Expected >= revision {
		return false
	}
	var put RegistryPut
	if canonical(definition.Change.Payload, &put) != nil {
		return false
	}
	put.Spec.Enabled = spec.Enabled
	if put.Spec != spec {
		return false
	}
	if origin.Change.Action == "put-registry" {
		a, aerr := definition.Command()
		b, berr := origin.Command()
		return aerr == nil && berr == nil && a == b
	}
	var start RegistrySelection
	return origin.Change.Action == "start-registry" && canonical(origin.Change.Payload, &start) == nil && start.Tenant == spec.Tenant && start.ID == spec.ID
}

func registryEndpoints(book Registries) error {
	ports := map[string]string{}
	authorities := map[string]string{}
	for key, row := range book.entries {
		var specs []registry.Specification
		if !row.Deleted {
			specs = append(specs, row.Spec)
		}
		if row.Active != nil {
			specs = append(specs, row.Active.Spec)
		}
		for _, spec := range specs {
			// A dedicated TCP port per node avoids wildcard/dual-stack overlap.
			port := spec.Address[strings.LastIndex(spec.Address, ":")+1:]
			slot := spec.Node + "/" + port
			if old, ok := ports[slot]; ok && old != key {
				return ErrCatalog
			}
			ports[slot] = key
			if old, ok := authorities[spec.Authority]; ok && old != key {
				return ErrCatalog
			}
			authorities[spec.Authority] = key
		}
	}
	return nil
}
func (p Policy) registryCheckpoint(s state.State, book Registries) (map[string][]byte, state.Code) {
	if book.Revision == ^uint64(0) || registryEndpoints(book) != nil {
		return nil, state.ConditionFailed
	}
	external, err := p.ExternalRegistries(s)
	if err != nil {
		return nil, state.Invalid
	}
	if externalRegistryScopes(external, book) != nil {
		return nil, state.ConditionFailed
	}
	book.Revision++
	raw, err := json.Marshal(registryCheckpoint{1, p.Cluster, book.Revision, book.Entries()})
	if err != nil {
		return nil, state.Invalid
	}
	return writeCheckpoint(s, RegistriesKey, p.Cluster, p.TrustRoot, book.Revision, raw)
}

func (p Policy) registryVolume(v Volumes, spec registry.Specification) (registeredVolume, error) {
	e, ok := v.entries[volumeKey(spec.Volume)]
	owner, _ := e.State.Owner()
	if !ok || e.State.Scope() != spec.Volume || e.State.Deleting() || e.State.Deleted() || !e.State.RetainsData() || spec.Enabled && owner.Node != spec.Node || spec.Volume.TenantManaged() != e.State.Fixed() {
		return e, ErrCatalog
	}
	return e, nil
}
func (p Policy) validateRegistryRefs(book Registries, v Volumes, r Resources) error {
	for _, entry := range book.entries {
		if !entry.Deleted {
			if _, err := p.registryVolume(v, entry.Spec); err != nil {
				return err
			}
		}
		if run := entry.Active; run != nil {
			e, ok := v.entries[volumeKey(run.Spec.Volume)]
			if !ok || e.State.Scope() != run.Spec.Volume || !slices.Contains(e.State.Consumers(), run.Consumer) || !slices.Contains(e.Grants, volumeGrant{run.Consumer, run.Principal}) {
				return ErrCatalog
			}
			quota, ok := r.Quotas.Reservation(run.Spec.BudgetKey())
			if !ok || quota != run.Budget {
				return ErrCatalog
			}
			for _, tenant := range []string{"", run.Spec.Tenant} {
				limit, ok := r.Quotas.Limit(tenant, run.Spec.Node)
				if !ok || limit.Owner != run.Owner || limit.MaxConsumers < run.Spec.MaxRequests {
					return ErrCatalog
				}
			}
		}
	}
	// A registry's writer and budget cannot survive without their parent.
	for _, e := range v.entries {
		for _, consumer := range e.State.Consumers() {
			reserved := e.State.Scope().RegistryManaged()
			found := false
			for _, parent := range book.entries {
				reserved = reserved || consumer.ID == registryConsumer(p.Cluster, parent.Spec.Tenant, parent.Spec.ID)
				if parent.Active != nil && parent.Active.Consumer == consumer && parent.Active.Spec.Volume == e.State.Scope() {
					found = true
				}
			}
			if reserved && !found {
				return ErrCatalog
			}
		}
	}
	for _, q := range r.Quotas.Reservations() {
		if !q.ManagedRegistry {
			continue
		}
		found := false
		for _, parent := range book.entries {
			if parent.Active != nil && parent.Active.Budget == q {
				found = true
				break
			}
		}
		if !found {
			return ErrCatalog
		}
	}
	return nil
}

func (p Policy) authorizeRegistry(c access.Catalog, op UserOperation) error {
	return p.authorizeRegistryChange(c, op.Session, op.At, op.Change)
}

func (p Policy) authorizeRegistryChange(c access.Catalog, session access.Session, at int64, change Change) error {
	if err := c.OperationAllowed(session, change.Action); err != nil {
		return err
	}
	var selection RegistrySelection
	node := ""
	cleanup := change.Action == "stop-registry" || change.Action == "delete-registry"
	if change.Action == "put-registry" {
		var q RegistryPut
		if canonical(change.Payload, &q) != nil || q.Spec.Validate(p.Cluster) != nil {
			return access.ErrInvalid
		}
		selection = RegistrySelection{q.Spec.Tenant, q.Spec.ID}
		node = q.Spec.Node
	} else {
		if canonical(change.Payload, &selection) != nil || selection.Tenant == "" || selection.ID == "" {
			return access.ErrInvalid
		}
	}
	if cleanup {
		return c.AuthorizeSessionCleanup(session, p.Cluster, p.Issuer(session.Issuer), at, selection.Tenant, access.ManageRegistry)
	}
	if err := c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, selection.Tenant, access.ManageRegistry, node); err != nil {
		return err
	}
	return c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, selection.Tenant, access.ManageVolumes, node)
}

func (p Policy) reduceRegistries(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	if strings.HasPrefix(cmd.Actor, "node/") {
		return p.reduceRegistryReport(s, cmd)
	}
	if cmd.Kind != state.Module || cmd.Key != RegistriesKey || !strings.HasPrefix(cmd.Actor, "user/") {
		return nil, state.Forbidden
	}
	p, err := p.Current(s)
	if err != nil {
		return nil, state.Invalid
	}
	users, err := p.Catalog(s)
	if err != nil {
		return nil, state.Invalid
	}
	op, err := p.Operation(users, cmd, false)
	if err != nil || p.authorizeRegistry(users, op) != nil {
		return nil, state.Forbidden
	}
	book, err := p.Registries(s)
	if err != nil {
		return nil, state.Invalid
	}
	var spec registry.Specification
	var selection RegistrySelection
	if op.Change.Action == "put-registry" {
		var q RegistryPut
		if canonical(op.Change.Payload, &q) != nil {
			return nil, state.Invalid
		}
		spec = q.Spec
		selection = RegistrySelection{spec.Tenant, spec.ID}
	} else {
		if canonical(op.Change.Payload, &selection) != nil {
			return nil, state.Invalid
		}
	}
	key := selection.Tenant + "/" + selection.ID
	if held, err := p.RegistryMaintenancePending(s, selection.Tenant, selection.ID); err != nil || held {
		return nil, state.ConditionFailed
	}
	entry, exists := book.entries[key]
	if op.Change.Action == "put-registry" && !exists {
		if op.Change.Expected != 0 || len(book.entries) >= maxRegistries {
			return nil, state.ConditionFailed
		}
		owner, err := p.nodeOwner(s, spec.Node)
		if err != nil {
			return nil, state.Forbidden
		}
		entry = RegistryEntry{Spec: spec, Revision: 1, DataOwner: owner, Initial: op, Definition: op, Origin: op}
	} else {
		if !exists || entry.Deleted || entry.Revision != op.Change.Expected {
			return nil, state.ConditionFailed
		}
		switch op.Change.Action {
		case "put-registry":
			if spec.Volume != entry.Spec.Volume {
				return nil, state.Invalid
			}
			entry.Spec = spec
			entry.Definition = op
			entry.Origin = op
		case "start-registry":
			entry.Spec.Enabled = true
			entry.Origin = op
		case "stop-registry":
			entry.Spec.Enabled = false
		case "delete-registry":
			if entry.Spec.Enabled || entry.Active != nil {
				return nil, state.ConditionFailed
			}
			entry.Deleted = true
		default:
			return nil, state.Invalid
		}
		if entry.Revision == ^uint64(0) {
			return nil, state.Invalid
		}
		entry.Revision++
	}
	if !entry.Deleted {
		v, err := p.Volumes(s)
		if err != nil {
			return nil, state.Invalid
		}
		row, volumeErr := p.registryVolume(v, entry.Spec)
		owner, _ := row.State.Owner()
		if volumeErr != nil || !exists && owner.Node != entry.Spec.Node {
			return nil, state.ConditionFailed
		}
		if entry.Spec.Enabled {
			if p.registryEnabledAllowed(s, users, op.Session, op.At, entry.Spec) != nil {
				return nil, state.Forbidden
			}
		}
	}
	book.entries[key] = entry
	return p.registryCheckpoint(s, book)
}

// RegistryPage is metadata-only: no login bearer, private key or native Ready
// is invented from an enabled desired definition.
type RegistryView struct {
	Spec                 registry.Specification
	Revision, Generation uint64
	Deleted, Draining    bool
	Active               bool                        `json:",omitempty"`
	Observation          *RegistryObservation        `json:",omitempty"`
	Maintenance          *RegistryMaintenanceSummary `json:",omitempty"`
}

func (p Policy) RegistryPage(s state.State, session access.Session, now int64, tenant, after string) ([]RegistryView, string, error) {
	p, err := p.Current(s)
	if err != nil {
		return nil, "", err
	}
	c, err := p.Catalog(s)
	if err != nil {
		return nil, "", err
	}
	if c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), now, tenant, access.Read, "") != nil && c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), now, tenant, access.ManageRegistry, "") != nil {
		return nil, "", access.ErrDenied
	}
	book, err := p.Registries(s)
	if err != nil {
		return nil, "", err
	}
	jobs, err := p.RegistryMaintenanceJobs(s)
	if err != nil {
		return nil, "", err
	}
	var rows []RegistryView
	for _, entry := range book.Entries() {
		if entry.Spec.Tenant != tenant || entry.Spec.Key() <= after {
			continue
		}
		if len(rows) == 8 {
			return rows, rows[len(rows)-1].Spec.Key(), nil
		}
		view := registryPublicView(entry)
		view.Maintenance = jobs.Summary(tenant, entry.Spec.ID)
		rows = append(rows, view)
	}
	return rows, "", nil
}

// registriesBook is the RegistriesKey book (books.go).
var registriesBook = Book{Key: RegistriesKey, Reduce: byKind(map[state.CommandKind]reducer{state.Module: Policy.reduceRegistries, state.ModuleReport: Policy.reduceRegistries})}
