// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"slices"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/registry"
	"github.com/jay94ks/mydcd/internal/tenancy"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

type RegistryReport struct {
	Schema                                               uint8
	Cluster, Reporter                                    [32]byte
	Tenant, ID, Action                                   string
	SpecRevision, Generation, Epoch, RootRevision, Index uint64
	At                                                   int64
	Observation                                          *RegistryObservation        `json:",omitempty"`
	Gone                                                 *volumes.Gone               `json:",omitempty"`
	Budget                                               *tenancy.ReservationClosure `json:",omitempty"`
	Signature                                            []byte
}

func RegistryReportBytes(r RegistryReport) []byte {
	r.Signature = nil
	raw, _ := json.Marshal(r)
	return append([]byte("mydc-registry-report-1\x00"), raw...)
}
func (r RegistryReport) Command() (state.Command, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return state.Command{}, err
	}
	c := state.Command{Kind: state.ModuleReport, Actor: "node/" + hex.EncodeToString(r.Reporter[:]), Epoch: r.Epoch, Key: RegistriesKey, Expected: r.RootRevision, Value: string(raw)}
	c.RequestID = state.ReportRequestID(c)
	_, err = state.EncodeCommand(c)
	return c, err
}
func (p Policy) registryReport(s state.State, c state.Command) (RegistryReport, error) {
	var r RegistryReport
	if c.Kind != state.ModuleReport || c.Key != RegistriesKey || canonical([]byte(c.Value), &r) != nil || r.Schema != 1 || r.Cluster != p.Cluster || r.Reporter == ([32]byte{}) || r.Epoch != s.ModuleEpoch() || r.At <= 0 || r.Index == 0 || r.Index > s.Index() || !ed25519.Verify(r.Reporter[:], RegistryReportBytes(r), r.Signature) {
		return r, ErrCatalog
	}
	want, err := r.Command()
	if err != nil || c != want {
		return r, ErrCatalog
	}
	d, err := p.Members(s)
	if err != nil || !d.MemberKey(r.Reporter) {
		return r, access.ErrDenied
	}
	switch r.Action {
	case "reserve", "drain":
		if r.Observation != nil || r.Gone != nil || r.Budget != nil {
			return r, ErrCatalog
		}
	case "serving":
		if r.Observation == nil || r.Gone != nil || r.Budget != nil || r.Observation.At != r.At || r.Observation.Boot == ([32]byte{}) || r.Observation.Certificate == ([32]byte{}) {
			return r, ErrCatalog
		}
	case "closed":
		if r.Observation != nil || r.Gone == nil || r.Budget == nil {
			return r, ErrCatalog
		}
	default:
		return r, ErrCatalog
	}
	return r, nil
}
func (p Policy) ResolveRegistryReport(s state.State, caller [32]byte, raw []byte) (state.Command, error) {
	var r RegistryReport
	if canonical(raw, &r) != nil || r.Reporter != caller {
		return state.Command{}, access.ErrDenied
	}
	c, err := r.Command()
	if err != nil {
		return c, err
	}
	_, err = p.registryReport(s, c)
	return c, err
}

func (p Policy) registryStartAllowed(s state.State, c access.Catalog, entry RegistryEntry) error {
	if entry.Deleted || !entry.Spec.Enabled {
		return access.ErrDenied
	}
	if _, err := p.workNodeOwner(s, entry.Spec.Node); err != nil {
		return err
	}
	for _, action := range []access.Action{access.ManageRegistry, access.ManageVolumes} {
		if c.AuthorizeAccepted(entry.Origin.Session, p.Cluster, entry.Origin.At, entry.Spec.Tenant, action, entry.Spec.Node) != nil {
			return access.ErrDenied
		}
	}
	return nil
}

type RegistryWorkRequest struct {
	RegistrySelection
	At int64
}
type RegistryWork struct {
	Entry                      RegistryWorkEntry
	MayStart                   bool
	Index, Epoch, RootRevision uint64
	Native                     *volumes.NativeReady `json:",omitempty"`
}

// Work carries verified references, not several copies of potentially large
// original user sessions/signatures. The full accepted grants stay in the FSM.
type RegistryRunRef struct {
	Generation, SpecRevision       uint64
	Spec                           registry.Specification
	Owner                          [32]byte
	Principal                      string
	DefinitionDigest, OriginDigest [32]byte
	Consumer                       volumes.Consumer
	Budget                         tenancy.Reservation
	Draining                       bool
	Ready                          *RegistryObservation `json:",omitempty"`
}
type RegistryClosureRef struct {
	Run    RegistryRunRef
	Gone   volumes.Gone
	Budget tenancy.ReservationClosure
}
type RegistryWorkEntry struct {
	Spec                 registry.Specification
	Revision, Generation uint64
	DataOwner            [32]byte
	Deleted              bool
	Active               *RegistryRunRef     `json:",omitempty"`
	Closed               *RegistryClosureRef `json:",omitempty"`
}

func (run RegistryRun) Reference() RegistryRunRef {
	definition, _ := run.Definition.Command()
	origin, _ := run.Origin.Command()
	var ready *RegistryObservation
	if run.Ready != nil {
		copy := *run.Ready
		ready = &copy
	}
	return RegistryRunRef{Generation: run.Generation, SpecRevision: run.SpecRevision, Spec: run.Spec, Owner: run.Owner, Principal: run.Principal, DefinitionDigest: state.Digest(definition), OriginDigest: state.Digest(origin), Consumer: run.Consumer, Budget: run.Budget, Draining: run.Draining, Ready: ready}
}
func registryWorkEntry(entry RegistryEntry) RegistryWorkEntry {
	view := RegistryWorkEntry{Spec: entry.Spec, Revision: entry.Revision, Generation: entry.Generation, DataOwner: entry.DataOwner, Deleted: entry.Deleted}
	if entry.Active != nil {
		run := entry.Active.Reference()
		view.Active = &run
	}
	if entry.Closed != nil {
		view.Closed = &RegistryClosureRef{Run: entry.Closed.Run.Reference(), Gone: entry.Closed.Gone, Budget: entry.Closed.Budget}
	}
	return view
}

func (p Policy) RegistryWork(s state.State, caller [32]byte, q RegistryWorkRequest) (RegistryWork, error) {
	if q.At <= 0 || caller == ([32]byte{}) {
		return RegistryWork{}, access.ErrDenied
	}
	book, err := p.Registries(s)
	if err != nil {
		return RegistryWork{}, err
	}
	entry, ok := book.Entry(q.Tenant, q.ID)
	if !ok {
		return RegistryWork{}, access.ErrDenied
	}
	owner, ownerErr := p.nodeOwner(s, entry.Spec.Node)
	if (ownerErr != nil || owner != caller) && (entry.Active == nil || entry.Active.Owner != caller) {
		return RegistryWork{}, access.ErrDenied
	}
	if entry.Active != nil {
		if current, e := p.nodeOwner(s, entry.Active.Spec.Node); e != nil || current != entry.Active.Owner {
			return RegistryWork{}, access.ErrDenied
		}
	}
	c, err := p.Catalog(s)
	if err != nil {
		return RegistryWork{}, err
	}
	work := RegistryWork{Entry: registryWorkEntry(entry), Index: s.Index(), Epoch: s.ModuleEpoch(), RootRevision: s.Object(RegistriesKey).Revision}
	work.MayStart = ownerErr == nil && owner == caller && p.registryStartAllowed(s, c, entry) == nil
	if entry.Active != nil {
		work.MayStart = work.MayStart && !entry.Active.Draining && entry.Active.SpecRevision == entry.Revision && entry.Active.Spec == entry.Spec
	}
	if work.MayStart {
		v, e := p.Volumes(s)
		if e != nil {
			return RegistryWork{}, e
		}
		row, e := p.registryVolume(v, entry.Spec)
		volumeOwner, _ := row.State.Owner()
		if e != nil || volumeOwner.Key != owner || p.canUseFixedVolume(s, c, entry.Origin.Session.User, row) != nil {
			work.MayStart = false
		} else if entry.Active != nil {
			work.MayStart = row.State.CheckActivation(entry.Active.Consumer) == nil
		}
		if work.MayStart {
			ready := row.Native
			work.Native = &ready
		}
	}
	return work, nil
}

func (p Policy) reduceRegistryReport(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	r, err := p.registryReport(s, cmd)
	if err != nil {
		return nil, state.Forbidden
	}
	book, err := p.Registries(s)
	if err != nil {
		return nil, state.Invalid
	}
	entry, exists := book.entries[r.Tenant+"/"+r.ID]
	if !exists {
		return nil, state.Invalid
	}
	users, err := p.Catalog(s)
	if err != nil {
		return nil, state.Invalid
	}
	v, err := p.Volumes(s)
	if err != nil {
		return nil, state.Invalid
	}
	resources, err := p.Resources(s)
	if err != nil {
		return nil, state.Invalid
	}
	if r.Action == "reserve" {
		owner, e := p.nodeOwner(s, entry.Spec.Node)
		if e != nil || owner != r.Reporter || entry.Active != nil || entry.Generation == ^uint64(0) || r.Generation != entry.Generation+1 || r.SpecRevision != entry.Revision || p.registryStartAllowed(s, users, entry) != nil {
			return nil, state.Forbidden
		}
		row, e := p.registryVolume(v, entry.Spec)
		if e != nil {
			return nil, state.ConditionFailed
		}
		volumeOwner, _ := row.State.Owner()
		if volumeOwner.Key != r.Reporter {
			return nil, state.Forbidden
		}
		if p.canUseFixedVolume(s, users, entry.Origin.Session.User, row) != nil {
			return nil, state.Forbidden
		}
		projected, e := p.ProjectResources(s)
		if e != nil {
			return nil, state.Invalid
		}
		for _, scope := range []string{"", entry.Spec.Tenant} {
			limit, ok := projected.Resources.Quotas.Limit(scope, entry.Spec.Node)
			used, e := projected.Resources.Quotas.Usage(scope, entry.Spec.Node)
			if !ok || e != nil || limit.Owner != owner || used.CPU > limit.Capacity.CPU || used.Memory > limit.Capacity.Memory || entry.Spec.Budget.CPU > limit.Capacity.CPU-used.CPU || entry.Spec.Budget.Memory > limit.Capacity.Memory-used.Memory || entry.Spec.MaxRequests > limit.MaxConsumers {
				return nil, state.ConditionFailed
			}
		}
		var consumer volumes.Consumer
		row.State, consumer, e = row.State.Acquire(users, entry.Origin.Session.User, row.State.Revision(), registryConsumer(p.Cluster, r.Tenant, r.ID), r.Generation, true)
		if e != nil {
			return nil, state.ConditionFailed
		}
		row.Grants = append(row.Grants, volumeGrant{consumer, entry.Origin.Session.User})
		v.entries[volumeKey(entry.Spec.Volume)] = row
		resources.Quotas, e = resources.Quotas.ReserveRegistry(users, entry.Origin.Session.User, resources.Quotas.Revision(), tenancy.Reservation{Key: entry.Spec.BudgetKey(), Tenant: r.Tenant, Node: entry.Spec.Node, Owner: owner, Need: entry.Spec.Budget})
		if e != nil {
			return nil, state.ConditionFailed
		}
		budget, _ := resources.Quotas.Reservation(entry.Spec.BudgetKey())
		entry.Generation = r.Generation
		entry.Active = &RegistryRun{Generation: r.Generation, SpecRevision: entry.Revision, Spec: entry.Spec, Owner: owner, Principal: entry.Origin.Session.User, Definition: entry.Definition, Origin: entry.Origin, Consumer: consumer, Budget: budget}
	} else {
		run := entry.Active
		if run == nil || run.Owner != r.Reporter || run.Generation != r.Generation || run.SpecRevision != r.SpecRevision {
			return nil, state.ConditionFailed
		}
		switch r.Action {
		case "serving":
			if run.Draining || run.SpecRevision != entry.Revision || run.Spec != entry.Spec || p.registryStartAllowed(s, users, entry) != nil {
				return nil, state.Forbidden
			}
			row, ok := v.entries[volumeKey(run.Spec.Volume)]
			if !ok || row.State.CheckActivation(run.Consumer) != nil || p.canUseFixedVolume(s, users, run.Principal, row) != nil {
				return nil, state.ConditionFailed
			}
			if run.Ready != nil && r.At < run.Ready.At {
				return nil, state.ConditionFailed
			}
			run.Ready = r.Observation
		case "drain":
			if held, err := p.RegistryMaintenancePending(s, entry.Spec.Tenant, entry.Spec.ID); err != nil || held {
				return nil, state.ConditionFailed
			}
			resources.Quotas, err = resources.Quotas.DrainRegistryOwner(run.Budget.Key, run.Owner, run.Budget.Generation)
			if err != nil {
				return nil, state.ConditionFailed
			}
			run.Budget, _ = resources.Quotas.Reservation(run.Budget.Key)
			run.Draining = true
		case "closed":
			if held, err := p.RegistryImageBuildsPending(s, run.Reference()); err != nil || held {
				return nil, state.ConditionFailed
			}
			if !run.Draining || r.Gone.Scope != run.Spec.Volume || r.Gone.Consumer != run.Consumer || r.Budget.Key != run.Budget.Key || r.Budget.Generation != run.Budget.Generation {
				return nil, state.Forbidden
			}
			row, ok := v.entries[volumeKey(run.Spec.Volume)]
			if !ok {
				return nil, state.Invalid
			}
			row.State, err = row.State.Release(*r.Gone)
			if err != nil {
				return nil, state.ConditionFailed
			}
			row.Grants = slices.DeleteFunc(row.Grants, func(g volumeGrant) bool { return g.Consumer == run.Consumer })
			v.entries[volumeKey(run.Spec.Volume)] = row
			resources.Quotas, err = resources.Quotas.ReleaseRegistryOwner(*r.Budget)
			if err != nil {
				return nil, state.ConditionFailed
			}
			entry.Closed = &RegistryClosure{Run: *run, Gone: *r.Gone, Budget: *r.Budget}
			entry.Active = nil
		}
	}
	book.entries[entry.Spec.Key()] = entry
	out, code := p.registryCheckpoint(s, book)
	if code != state.Applied {
		return nil, code
	}
	if r.Action != "serving" {
		merge := func(values map[string][]byte, c state.Code) bool {
			if c != state.Applied {
				code = c
				return false
			}
			for key, value := range values {
				if _, exists := out[key]; exists {
					code = state.Invalid
					return false
				}
				out[key] = value
			}
			return true
		}
		if r.Action != "drain" && !merge(p.volumeCheckpoint(s, v)) {
			return nil, code
		}
		if !merge(p.resourceCheckpoint(s, resources)) {
			return nil, code
		}
	}
	return out, state.Applied
}
