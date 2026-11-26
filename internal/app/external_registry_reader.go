// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"sync"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/secrets"
)

type externalReaderSlot struct {
	generation uint64
	active     int
	fenced     bool
}

// The local pin covers the entire query, fetched material and registry I/O.
// Shared usage is retained until Drain plus this actual owner join; no file or
// native process is manufactured for a source-reader authorization record.
func (r *Runtime) acquireExternalReader(work control.ExternalRegistryWork) (func(), error) {
	r.externalReaderMu.Lock()
	defer r.externalReaderMu.Unlock()
	if work.Reader.Owner != r.Identity.Public || work.Reader.Draining || work.Reader.Generation == 0 || work.Reader.Spec.Validate() != nil {
		return nil, mydcp.ErrAdmission
	}
	if r.externalReaders == nil {
		r.externalReaders = map[string]*externalReaderSlot{}
	}
	key := work.Reader.Spec.Key()
	slot := r.externalReaders[key]
	if slot == nil || slot.generation < work.Reader.Generation && slot.active == 0 {
		slot = &externalReaderSlot{generation: work.Reader.Generation}
		r.externalReaders[key] = slot
	}
	if slot.generation != work.Reader.Generation || slot.fenced {
		return nil, mydcp.ErrAdmission
	}
	slot.active++
	var once sync.Once
	return func() { once.Do(func() { r.externalReaderMu.Lock(); slot.active--; r.externalReaderMu.Unlock() }) }, nil
}

func (r *Runtime) externalRegistryWork(ctx context.Context, selection control.ExternalRegistryReadSelection) (control.ExternalRegistryWork, error) {
	q := control.ExternalRegistryWorkRequest{Selection: selection, At: time.Now().Unix()}
	body, _ := json.Marshal(q)
	reply, err := r.appCall(ctx, "external-registry-work", body)
	if err != nil {
		return control.ExternalRegistryWork{}, err
	}
	work, err := schema.Decode[control.ExternalRegistryWork](reply.Data)
	if err != nil || reply.Local || work.Index == 0 || work.Epoch == 0 || work.Reader.Spec.Tenant != selection.Tenant || work.Reader.Spec.ID != selection.ID || work.Reader.Generation != selection.Generation || work.Reader.Owner != r.Identity.Public {
		return control.ExternalRegistryWork{}, mydcp.ErrAdmission
	}
	view, err := r.Engine().ReadAtLeast(ctx, work.Index)
	if err != nil || view.State.ModuleEpoch() != work.Epoch {
		return control.ExternalRegistryWork{}, mydcp.ErrAdmission
	}
	current, err := r.controlPolicy.ExternalRegistryWork(view.State, r.Identity.Public, q)
	if err != nil || current.Inputs.ReadSet != work.Inputs.ReadSet {
		return control.ExternalRegistryWork{}, mydcp.ErrAdmission
	}
	return work, nil
}

func (r *Runtime) reconcileExternalRegistryReaders(ctx context.Context, view cluster.View) error {
	entries, err := r.controlPolicy.ExternalRegistries(view.State)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		reader := entry.Reader
		if reader == nil || reader.Owner != r.Identity.Public || !reader.Draining {
			continue
		}
		if !r.fenceExternalReader(*reader) {
			continue
		}
		selection := control.ExternalRegistryReadSelection{Tenant: reader.Spec.Tenant, ID: reader.Spec.ID, Generation: reader.Generation}
		if held, err := r.controlPolicy.ExternalRegistryImageBuildsPending(view.State, selection); err != nil {
			return err
		} else if held {
			continue
		}
		proof := control.ExternalRegistryReaderClosed{Schema: 1, Cluster: r.controlPolicy.Cluster, Owner: r.Identity.Public, Tenant: entry.Spec.Tenant, ID: entry.Spec.ID, Generation: reader.Generation, Index: view.State.Index(), Epoch: view.State.ModuleEpoch(), RootRevision: view.State.Object(control.ExternalRegistriesKey).Revision, At: time.Now().Unix(), Closed: true}
		for _, grant := range reader.Grants {
			use := grant.Use
			gone := secrets.UseGone{Purpose: use.Purpose, Cluster: r.controlPolicy.Cluster, Realm: grant.Realm, Tenant: use.Tenant, App: use.App, Deployment: use.Deployment, Consumer: grant.Consumer, Generation: grant.Generation, NodeKey: r.Identity.Public, Selection: grant.Selection, Lifetime: grant.Lifetime, Stopped: true, MountsGone: true}
			gone.Signature = ed25519.Sign(r.Identity.Private, secrets.UseGoneBytes(gone))
			proof.Secrets = append(proof.Secrets, gone)
		}
		proof.Signature = ed25519.Sign(r.commandIdentity().Private, control.ExternalRegistryReaderClosedBytes(proof))
		body, _ := json.Marshal(proof)
		if _, err := r.appCall(ctx, "external-registry-closed", body); err != nil {
			return err
		}
		// One original closure per view; the next pass uses the new root CAS.
		return nil
	}
	return nil
}

// Fence rejects new calls before inspecting the active count. The signed owner
// closure is emitted only after each existing call has closed its clients and
// fetched material and released the original pin.
func (r *Runtime) fenceExternalReader(reader control.ExternalRegistryReader) bool {
	r.externalReaderMu.Lock()
	defer r.externalReaderMu.Unlock()
	if reader.Owner != r.Identity.Public || reader.Generation == 0 || !reader.Draining {
		return false
	}
	if r.externalReaders == nil {
		r.externalReaders = map[string]*externalReaderSlot{}
	}
	key := reader.Spec.Key()
	slot := r.externalReaders[key]
	if slot == nil {
		slot = &externalReaderSlot{generation: reader.Generation}
		r.externalReaders[key] = slot
	}
	if slot.generation > reader.Generation || slot.generation < reader.Generation && slot.active != 0 {
		return false
	}
	if slot.generation < reader.Generation {
		slot = &externalReaderSlot{generation: reader.Generation}
		r.externalReaders[key] = slot
	}
	slot.fenced = true
	return slot.active == 0
}
