// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/imagesource"
)

const ExternalRegistriesKey = "control/external-registries"
const maxExternalRegistries = 256

type ExternalRegistryPut struct{ Spec imagesource.Source }
type ExternalRegistryEntry struct {
	Spec               imagesource.Source
	Revision           uint64
	Deleted            bool
	Definition, Origin UserOperation
	Reader             *ExternalRegistryReader        `json:",omitempty"`
	Closed             *ExternalRegistryReaderClosure `json:",omitempty"`
}
type externalRegistryCheckpoint struct {
	Schema   uint8
	Cluster  [32]byte
	Revision uint64
	Entries  []ExternalRegistryEntry
}

// ExternalRegistries validates accepted signed definitions, including retained
// tombstones. No provider read or ambient host credential participates in FSM.
func (p Policy) ExternalRegistries(s state.State) ([]ExternalRegistryEntry, error) {
	raw, revision, err := readCheckpoint(s, ExternalRegistriesKey, p.Cluster, p.TrustRoot)
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}
	var disk externalRegistryCheckpoint
	if canonical(raw, &disk) != nil || disk.Schema != 1 || disk.Cluster != p.Cluster || disk.Revision != revision || revision == 0 || len(disk.Entries) > maxExternalRegistries {
		return nil, ErrCatalog
	}
	c, err := p.Catalog(s)
	if err != nil {
		return nil, err
	}
	managed, err := p.Registries(s)
	if err != nil {
		return nil, err
	}
	vault, err := p.Vault(s)
	if err != nil {
		return nil, err
	}
	last := ""
	for _, e := range disk.Entries {
		if e.Spec.Validate() != nil || e.Spec.Key() <= last || e.Revision == 0 || e.Definition.VerifyOriginal(p.Cluster) != nil || e.Origin.VerifyOriginal(p.Cluster) != nil || e.Origin.Change.Expected != e.Revision-1 || e.Definition.Change.Action != "put-external-registry" || e.Definition.Change.Expected >= e.Revision {
			return nil, ErrCatalog
		}
		last = e.Spec.Key()
		if _, ok := c.Tenant(e.Spec.Tenant); !ok {
			return nil, ErrCatalog
		}
		var put ExternalRegistryPut
		if canonical(e.Definition.Change.Payload, &put) != nil || !imagesource.Equal(put.Spec, e.Spec) {
			return nil, ErrCatalog
		}
		if e.Origin.Change.Action == "delete-external-registry" {
			var q RegistrySelection
			if !e.Deleted || canonical(e.Origin.Change.Payload, &q) != nil || q.Tenant != e.Spec.Tenant || q.ID != e.Spec.ID {
				return nil, ErrCatalog
			}
		} else if e.Origin.Change.Action == "put-external-registry" {
			a, ae := e.Definition.Command()
			b, be := e.Origin.Command()
			if e.Deleted || ae != nil || be != nil || a != b {
				return nil, ErrCatalog
			}
		} else if e.Origin.Change.Action == "bind-external-registry" {
			if e.Deleted || e.Reader == nil || e.Reader.Draining || e.Reader.Generation != e.Revision {
				return nil, ErrCatalog
			}
			a, ae := e.Origin.Command()
			b, be := e.Reader.Origin.Command()
			if ae != nil || be != nil || a != b {
				return nil, ErrCatalog
			}
		} else if e.Origin.Change.Action == "unbind-external-registry" {
			var q RegistrySelection
			if e.Deleted || canonical(e.Origin.Change.Payload, &q) != nil || q.Tenant != e.Spec.Tenant || q.ID != e.Spec.ID || e.Reader == nil && e.Closed == nil {
				return nil, ErrCatalog
			}
		} else {
			return nil, ErrCatalog
		}
		if r := e.Reader; r != nil {
			if e.Origin.Change.Action != "bind-external-registry" && !r.Draining {
				return nil, ErrCatalog
			}
			if !p.validExternalRegistryReader(s, *r, RegistrySelection{e.Spec.Tenant, e.Spec.ID}) || r.Generation > e.Revision || (!r.Draining && (e.Deleted || !imagesource.Equal(r.Spec, e.Spec))) {
				return nil, ErrCatalog
			}
			for _, grant := range r.Grants {
				if _, ok := vault.Approvals.Usage(grant); !ok {
					return nil, ErrCatalog
				}
			}
		}
		if closed := e.Closed; closed != nil {
			if !closed.Reader.Draining || !p.validExternalRegistryReader(s, closed.Reader, RegistrySelection{e.Spec.Tenant, e.Spec.ID}) || !p.validExternalRegistryClosure(closed.Reader, closed.Proof) || closed.Reader.Generation > e.Revision || e.Reader != nil && closed.Reader.Generation >= e.Reader.Generation {
				return nil, ErrCatalog
			}
		}
	}
	if externalRegistryScopes(disk.Entries, managed) != nil {
		return nil, ErrCatalog
	}
	return disk.Entries, nil
}

func externalRegistryScopes(entries []ExternalRegistryEntry, managed Registries) error {
	selectors := map[string]bool{}
	for _, e := range entries {
		selector := e.Spec.Tenant + "/" + e.Spec.Authority + "/" + e.Spec.Repository
		if selectors[selector] {
			return ErrCatalog
		}
		selectors[selector] = true
		for _, m := range managed.Entries() {
			if m.Spec.Authority == e.Spec.Authority || m.Active != nil && m.Active.Spec.Authority == e.Spec.Authority {
				return ErrCatalog
			}
		}
	}
	return nil
}

func (p Policy) authorizeExternalRegistry(c access.Catalog, op UserOperation) error {
	if err := c.OperationAllowed(op.Session, op.Change.Action); err != nil {
		return err
	}
	var q RegistrySelection
	switch op.Change.Action {
	case "put-external-registry":
		var put ExternalRegistryPut
		if canonical(op.Change.Payload, &put) != nil || put.Spec.Validate() != nil {
			return access.ErrInvalid
		}
		q = RegistrySelection{put.Spec.Tenant, put.Spec.ID}
	case "bind-external-registry":
		var bind ExternalRegistryBind
		if canonical(op.Change.Payload, &bind) != nil || !validID(bind.Tenant) || !validID(bind.ID) || !validID(bind.Node) || bind.Definition == ([32]byte{}) {
			return access.ErrInvalid
		}
		if c.AuthorizeSession(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, bind.Tenant, access.Deploy, bind.Node) != nil {
			return access.ErrDenied
		}
		return c.AuthorizeSession(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, bind.Tenant, access.ManageRegistry, bind.Node)
	case "delete-external-registry", "unbind-external-registry":
		if canonical(op.Change.Payload, &q) != nil || !validID(q.Tenant) || !validID(q.ID) {
			return access.ErrInvalid
		}
	default:
		return access.ErrInvalid
	}
	if op.Change.Action == "delete-external-registry" || op.Change.Action == "unbind-external-registry" {
		return c.AuthorizeSessionCleanup(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, q.Tenant, access.ManageRegistry)
	}
	return c.AuthorizeSession(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, q.Tenant, access.ManageRegistry, "")
}

// Public projection intentionally excludes accepted operation/session proofs.
type ExternalRegistryView struct {
	Spec     imagesource.Source
	Revision uint64
	Deleted  bool
	Reader   *ExternalRegistryReaderView `json:",omitempty"`
}
type ExternalRegistryReaderView struct {
	Node       string
	Owner      [32]byte
	Generation uint64
	Draining   bool
}

func (p Policy) ExternalRegistryPage(s state.State, session access.Session, at int64, tenant, after string) ([]ExternalRegistryView, string, error) {
	p, err := p.Current(s)
	if err != nil {
		return nil, "", err
	}
	c, err := p.Catalog(s)
	if err != nil {
		return nil, "", err
	}
	if tenant == "" || len(after) > 512 || c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.Read, "") != nil && c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.ManageRegistry, "") != nil {
		return nil, "", access.ErrDenied
	}
	entries, err := p.ExternalRegistries(s)
	if err != nil {
		return nil, "", err
	}
	var rows []ExternalRegistryView
	for _, e := range entries {
		if e.Spec.Tenant != tenant || e.Spec.Key() <= after {
			continue
		}
		if len(rows) == 8 {
			return rows, rows[len(rows)-1].Spec.Key(), nil
		}
		row := ExternalRegistryView{Spec: imagesource.Own(e.Spec), Revision: e.Revision, Deleted: e.Deleted}
		if r := e.Reader; r != nil {
			row.Reader = &ExternalRegistryReaderView{r.Node, r.Owner, r.Generation, r.Draining}
		}
		rows = append(rows, row)
	}
	return rows, "", nil
}

func (p Policy) reduceExternalRegistries(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	if cmd.Kind == state.ModuleReport {
		return p.reduceExternalRegistryClose(s, cmd)
	}
	if cmd.Kind != state.Module || !strings.HasPrefix(cmd.Actor, "user/") {
		return nil, state.Forbidden
	}
	p, err := p.Current(s)
	if err != nil {
		return nil, state.Invalid
	}
	c, err := p.Catalog(s)
	if err != nil {
		return nil, state.Invalid
	}
	op, err := p.Operation(c, cmd, false)
	if err != nil || p.authorizeExternalRegistry(c, op) != nil {
		return nil, state.Forbidden
	}
	entries, err := p.ExternalRegistries(s)
	if err != nil {
		return nil, state.Invalid
	}
	var put ExternalRegistryPut
	var q RegistrySelection
	var bind ExternalRegistryBind
	if op.Change.Action == "put-external-registry" {
		if canonical(op.Change.Payload, &put) != nil {
			return nil, state.Invalid
		}
		q = RegistrySelection{put.Spec.Tenant, put.Spec.ID}
	} else if op.Change.Action == "bind-external-registry" {
		if canonical(op.Change.Payload, &bind) != nil {
			return nil, state.Invalid
		}
		q = RegistrySelection{bind.Tenant, bind.ID}
	} else if canonical(op.Change.Payload, &q) != nil {
		return nil, state.Invalid
	}
	i := slices.IndexFunc(entries, func(e ExternalRegistryEntry) bool { return e.Spec.Tenant == q.Tenant && e.Spec.ID == q.ID })
	var entry ExternalRegistryEntry
	if i >= 0 {
		entry = entries[i]
	}
	if entry.Revision != op.Change.Expected || entry.Revision == ^uint64(0) {
		return nil, state.ConditionFailed
	}
	var updatedVault *Vault
	if op.Change.Action == "bind-external-registry" {
		reader, vault, err := p.bindExternalRegistry(s, entry, op, bind)
		if err != nil {
			return nil, state.ConditionFailed
		}
		entry.Reader = &reader
		if len(reader.Grants) > 0 {
			updatedVault = &vault
		}
	} else if op.Change.Action == "unbind-external-registry" {
		if i < 0 || entry.Deleted || entry.Reader == nil || entry.Reader.Draining {
			return nil, state.ConditionFailed
		}
		entry.Reader.Draining = true
	} else if op.Change.Action == "delete-external-registry" {
		if i < 0 || entry.Deleted {
			return nil, state.ConditionFailed
		}
		entry.Deleted = true
		if entry.Reader != nil {
			entry.Reader.Draining = true
		}
	} else {
		// Scope is immutable: editing an authority must not silently turn its
		// previous matching images into anonymous pulls. Use an explicit new ID.
		if i >= 0 && (entry.Spec.Authority != put.Spec.Authority || entry.Spec.Repository != put.Spec.Repository) {
			return nil, state.ConditionFailed
		}
		entry.Spec, entry.Deleted, entry.Definition = imagesource.Own(put.Spec), false, op
		if entry.Reader != nil {
			entry.Reader.Draining = true
		}
	}
	entry.Revision++
	entry.Origin = op
	if i < 0 {
		if len(entries) >= maxExternalRegistries {
			return nil, state.ConditionFailed
		}
		entries = append(entries, entry)
	} else {
		entries[i] = entry
	}
	writes, code := p.externalRegistryCheckpoint(s, entries)
	if code != state.Applied {
		return nil, code
	}
	if updatedVault != nil {
		extra, code := p.vaultCheckpoint(s, *updatedVault)
		if code != state.Applied {
			return nil, code
		}
		for k, v := range extra {
			writes[k] = v
		}
	}
	return writes, state.Applied
}

func (p Policy) externalRegistryCheckpoint(s state.State, entries []ExternalRegistryEntry) (map[string][]byte, state.Code) {
	slices.SortFunc(entries, func(a, b ExternalRegistryEntry) int { return strings.Compare(a.Spec.Key(), b.Spec.Key()) })
	managed, err := p.Registries(s)
	if err != nil {
		return nil, state.Invalid
	}
	if externalRegistryScopes(entries, managed) != nil {
		return nil, state.ConditionFailed
	}
	// Uniqueness and managed authority checks are also applied by Validate to
	// both directions of edits and snapshot adoption, before state is accepted.
	_, revision, err := readCheckpoint(s, ExternalRegistriesKey, p.Cluster, p.TrustRoot)
	if err != nil || revision == ^uint64(0) {
		return nil, state.Invalid
	}
	raw, err := json.Marshal(externalRegistryCheckpoint{1, p.Cluster, revision + 1, entries})
	if err != nil {
		return nil, state.Invalid
	}
	return writeCheckpoint(s, ExternalRegistriesKey, p.Cluster, p.TrustRoot, revision+1, raw)
}

func (p Policy) ExternalRegistryForImage(s state.State, tenant string, image access.Image) (*imagesource.Source, error) {
	definitions, err := p.externalRegistryDefinitions(s, tenant)
	if err != nil {
		return nil, err
	}
	selected, err := imagesource.Select(definitions, tenant, image)
	if err != nil {
		return nil, access.ErrDenied
	}
	return selected, nil
}

func (p Policy) externalRegistryDefinitions(s state.State, tenant string) ([]imagesource.Definition, error) {
	entries, err := p.ExternalRegistries(s)
	if err != nil {
		return nil, err
	}
	var definitions []imagesource.Definition
	for _, entry := range entries {
		if entry.Spec.Tenant == tenant {
			definitions = append(definitions, imagesource.Definition{Spec: imagesource.Own(entry.Spec), Deleted: entry.Deleted})
		}
	}
	return definitions, nil
}

// externalRegistriesBook is the ExternalRegistriesKey book (books.go).
var externalRegistriesBook = Book{Key: ExternalRegistriesKey, Reduce: Policy.reduceExternalRegistries}
