// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/json"
	"strings"
	"unicode/utf8"

	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/state"
)

const StorageKey = "control/storage"

type LedgerWindow struct{ NextEpoch uint64 }

type Storage struct {
	RotatedAt         uint64 `json:",omitempty"`
	RotatedBy         string `json:",omitempty"`
	RotationOperation string `json:",omitempty"`
	Schema            uint8
	Cluster           [32]byte
	Epoch             uint64
}

func (p Policy) Storage(s state.State) (Storage, error) {
	root := s.Object(StorageKey)
	if !root.Present {
		if root.Revision != 0 || s.ModuleEpoch() != 1 {
			return Storage{}, ErrCatalog
		}
		return Storage{Schema: 1, Cluster: p.Cluster, Epoch: 1}, nil
	}
	var storage Storage
	if canonical([]byte(root.Value), &storage) != nil || storage.Schema != 1 || storage.Cluster != p.Cluster || storage.Epoch != s.ModuleEpoch() || storage.Epoch < 2 || root.Revision != s.ModuleWindowRevision() {
		return Storage{}, ErrCatalog
	}
	if (storage.RotatedBy != "" || storage.RotatedAt != 0 || storage.RotationOperation != "") && (!lifecycle.ValidID(storage.RotatedBy) || storage.RotationOperation == "" || len(storage.RotationOperation) > 256 || !utf8.ValidString(storage.RotationOperation)) {
		return Storage{}, ErrCatalog
	}
	return storage, nil
}

// storageQuiescent checks the complete shared view, not a user's filtered view.
// Future adapters must join their original request references here before their
// namespaces become eligible. Never infer settlement from missing observation.
func (p Policy) storageQuiescent(s state.State) bool {
	if shells, err := p.NodeShells(s); err != nil || !shells.Quiescent() {
		return false
	}

	builds, buildErr := p.ImageBuilds(s)
	if buildErr != nil {
		return false
	}
	for _, row := range builds.CachePrunes {
		if row.Pending() {
			return false
		}
	}
	for _, job := range builds.Jobs {
		if !job.Run.Terminal() {
			return false
		}
	}
	for _, u := range builds.Uploads {
		if !u.Closed {
			return false
		}
	}
	if jobs, err := p.RegistryMaintenanceJobs(s); err != nil || !jobs.Quiescent() {
		return false
	}
	if jobs, err := p.ImageCacheJobs(s); err != nil || !jobs.Quiescent() {
		return false
	}
	if jobs, err := p.TunnelReconnections(s); err != nil || !jobs.Quiescent() {
		return false
	}
	if c, err := p.Compactions(s); err != nil || !c.Quiescent() {
		return false
	}
	if _, err := p.Catalog(s); err != nil {
		return false
	}
	if _, err := p.Resources(s); err != nil {
		return false
	}
	projection, err := p.ProjectResources(s)
	if err != nil {
		return false
	}
	dns, err := p.ManagedDNS(s)
	if err != nil {
		return false
	}
	if checkers, err := p.Lifecycles(s); err != nil || !checkers.Quiescent() {
		return false
	}
	registries, err := p.Registries(s)
	if err != nil {
		return false
	}
	for _, entry := range registries.entries {
		if entry.Active != nil {
			return false
		}
	}
	roots, err := p.NodeStorage(s)
	if err != nil {
		return false
	}
	external, sourceErr := p.ExternalRegistries(s)
	if sourceErr != nil {
		return false
	}
	for _, entry := range external {
		if entry.Reader != nil {
			return false
		}
	}
	for _, root := range roots.Roots() {
		if root.Attestation == nil && root.Closed == nil || root.Draining && root.Closed == nil {
			return false
		}
	}
	if volumes, err := p.Volumes(s); err != nil || !volumes.Quiescent() {
		return false
	}
	apps, err := p.Apps(s)
	if err != nil || !apps.Quiescent() {
		return false
	}
	vault, err := p.Vault(s)
	if err != nil || !vault.Quiescent() {
		return false
	}
	d, err := p.Members(s)
	if err != nil || !d.Quiescent() {
		return false
	}
	for key, object := range s.Objects("") {
		if !object.Present {
			continue
		}
		_, managedSource := projection.ManagedSources[key]
		_, dnsSource := dns[key]
		if !managedSource && !dnsSource && !bookStateKey(key) {
			return false
		}
	}
	return true
}

func (p Policy) reduceStorage(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	if cmd.Kind != state.ModuleWindow || cmd.Key != StorageKey {
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
	if err != nil || p.authorizeChange(s, c, op) != nil {
		return nil, state.Forbidden
	}
	var change LedgerWindow
	if op.Change.Action != "rotate-ledger" || canonical(op.Change.Payload, &change) != nil {
		return nil, state.Invalid
	}
	storage, err := p.Storage(s)
	if err != nil {
		return nil, state.Invalid
	}
	if op.Change.Expected != storage.Epoch || storage.Epoch == ^uint64(0) || change.NextEpoch != storage.Epoch+1 || !p.storageQuiescent(s) {
		return nil, state.ConditionFailed
	}
	storage.Epoch = change.NextEpoch
	storage.RotatedAt, storage.RotatedBy, storage.RotationOperation = uint64(op.At), op.Session.User, op.RequestID
	raw, err := json.Marshal(storage)
	if err != nil {
		return nil, state.Invalid
	}
	return map[string][]byte{StorageKey: raw}, state.Applied
}

// bookStateKey reports whether key belongs to a book (its root or under it)
// or is the storage key itself. Ledger rotation refuses any other key.
func bookStateKey(key string) bool {
	if key == StorageKey {
		return true
	}
	for _, root := range bookRoots {
		if key == root || strings.HasPrefix(key, root+"/") {
			return true
		}
	}
	return false
}
