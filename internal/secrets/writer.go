// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/storage"
)

// ErrNotCovered means this node's Vault profile does not cover the write's
// object and nothing was ever sent for it here: the write did not happen.
var ErrNotCovered = errors.New("the object is outside this node's Vault prefix")

// Writer owns only PUBLIC original provider intent and local A2 dispatch. The
// calling authenticated adapter supplies fresh authority before first use; no
// private values/verifiers/value hashes enter this journal. Unknown can only
// read back the original provider receipt, never issue another Put.
type Writer struct {
	journal  *reconcile.Journal
	provider *Vault
}
type providerIntent struct {
	Schema                             uint8
	Cluster                            [32]byte
	Realm                              string
	Request                            WriteRequest
	Actor                              string
	Generation, ExpectedObjectRevision uint64
	Writer                             WriteProfile
	Operation                          uint64
}

func originalProviderIntent(cluster [32]byte, realm string, w WriteRecord) (string, error) {
	if cluster == ([32]byte{}) || realm != "" && !identifier(realm) || w.Journal.LastID != 1 || w.Status() == "Invalid" || w.Status() == "Prepared" || w.Status() == "Abandoned" {
		return "", ErrProvider
	}
	raw, err := json.Marshal(providerIntent{1, cluster, realm, w.Request, w.Actor, w.Generation, w.ExpectedObjectRevision, w.Writer, w.Journal.LastID})
	return string(raw), err
}
func OpenWriter(path string, provider *Vault) (*Writer, error) {
	if provider == nil {
		return nil, ErrProvider
	}
	j, err := reconcile.OpenJournal(path)
	if err != nil {
		return nil, err
	}
	return &Writer{j, provider}, nil
}
func (m *Writer) Close() error { return m.journal.Close() }
func (m *Writer) Record(cluster [32]byte, realm string, w WriteRecord) (reconcile.Record, error) {
	return m.journal.Read(providerJournalKey(cluster, realm, w))
}
func providerJournalKey(cluster [32]byte, realm string, w WriteRecord) string {
	if realm == "" {
		realm = "cluster"
	} else {
		realm = "tenant/" + realm
	}
	return hex.EncodeToString(cluster[:]) + "/" + realm + "/" + strconv.FormatUint(w.Request.Epoch, 10) + "/" + w.Request.ID
}

// Apply executes once when both the shared intent and local journal permit it.
// recoverOnly is required after a client loses its first response. Read-back on
// an absent/mismatched provider record remains Unknown, even on a fresh writer.
func (m *Writer) Apply(ctx context.Context, cluster [32]byte, realm string, w WriteRecord, values map[string][]byte, recoverOnly bool) (ProviderReceipt, error) {
	spec, err := originalProviderIntent(cluster, realm, w)
	if err != nil {
		return ProviderReceipt{}, err
	}
	key := providerJournalKey(cluster, realm, w)
	if !m.provider.permits(w.Request.Profile, w.Request.ProviderObject) {
		if _, err := m.journal.Read(key); errors.Is(err, storage.ErrMissing) {
			// No local record: no Put was ever started for this write.
			return ProviderReceipt{}, fmt.Errorf("%w: %w: profile %s object %s", ErrProvider, ErrNotCovered, w.Request.Profile, w.Request.ProviderObject)
		}
		return ProviderReceipt{}, fmt.Errorf("%w: the local profile does not cover profile %s object %s", ErrProvider, w.Request.Profile, w.Request.ProviderObject)
	}
	desired := reconcile.Desired{Revision: w.Generation, Resource: reconcile.Resource{Generation: w.Generation, Spec: spec, Present: true}}
	if err = m.journal.Desired(key, desired, 1); err != nil {
		return ProviderReceipt{}, err
	}
	driver := providerDriver{provider: m.provider, original: w, values: values, spec: spec, recoverOnly: recoverOnly || w.Status() != "Dispatched"}
	if err = m.journal.Step(ctx, key, &driver); err != nil {
		return ProviderReceipt{}, providerCause(err)
	}
	record, err := m.journal.Read(key)
	if err != nil || record.State.Pending != nil || record.State.Applied != desired.Resource {
		return ProviderReceipt{}, fmt.Errorf("%w: the local write journal is not settled (%v)", ErrProvider, err)
	}
	return m.provider.ReadOriginal(ctx, w)
}

type providerDriver struct {
	provider    *Vault
	original    WriteRecord
	values      map[string][]byte
	spec        string
	recoverOnly bool
}

func (d *providerDriver) Execute(ctx context.Context, _ string, op reconcile.Operation) (reconcile.Outcome, error) {
	if op.Kind != reconcile.Apply || op.Target.Spec != d.spec || !op.Target.Present || op.Target.Generation != d.original.Generation {
		return reconcile.EffectUnknown, ErrProvider
	}
	if d.recoverOnly {
		return d.read(ctx)
	}
	if _, err := d.provider.PutOnce(ctx, d.original, d.values); err != nil {
		return reconcile.EffectUnknown, providerCause(err)
	}
	return reconcile.EffectApplied, nil
}
func (d *providerDriver) Recover(ctx context.Context, _ string, op reconcile.Operation) (reconcile.Outcome, error) {
	if op.Kind != reconcile.Apply || op.Target.Spec != d.spec || !op.Target.Present || op.Target.Generation != d.original.Generation {
		return reconcile.EffectUnknown, ErrProvider
	}
	return d.read(ctx)
}
func (d *providerDriver) read(ctx context.Context) (reconcile.Outcome, error) {
	if _, err := d.provider.ReadOriginal(ctx, d.original); err != nil {
		return reconcile.EffectUnknown, providerCause(err)
	}
	return reconcile.EffectApplied, nil
}

// providerCause keeps ErrProvider for callers and adds the cause for logs.
// Causes name profiles, objects and Vault errors, never values.
func providerCause(err error) error {
	if errors.Is(err, ErrProvider) {
		return err
	}
	return fmt.Errorf("%w: %v", ErrProvider, err)
}
