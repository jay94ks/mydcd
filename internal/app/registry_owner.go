// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/ingress"
	"github.com/jay94ks/seafield/internal/registry"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

const registryOwnerPrefix = "registry/owner/"

type registryOwnerRecord struct {
	Schema                           uint8
	Cluster, Owner, DataOwner        [32]byte
	Spec                             registry.Specification
	Generation, SpecRevision         uint64
	Native                           volumes.NativeReady
	Run                              *control.RegistryRunRef `json:",omitempty"`
	Phase                            string
	KnownData, IOClosed, PinReturned bool
	PinAttempted                     bool
	Pin                              *volumes.NativeLease `json:",omitempty"`
}
type registrySession struct {
	directory *volumes.DataDirectory
	store     *registry.Store
	server    *registry.Server
}

func registryRecordKey(tenant, id string) string { return registryOwnerPrefix + tenant + "/" + id }
func registryNativeConsumer(row registryOwnerRecord) string {
	return "registry/" + row.Spec.Tenant + "/" + row.Spec.ID + "/" + strconv.FormatUint(row.Generation, 10)
}
func (r *Runtime) saveRegistry(row registryOwnerRecord) error {
	if r.registryFailed.Load() {
		return registry.ErrUnavailable
	}
	raw, err := json.Marshal(row)
	if err != nil || len(raw) > 64<<10 {
		return registry.ErrStorage
	}
	if err = r.reports.Write(map[string][]byte{registryRecordKey(row.Spec.Tenant, row.Spec.ID): raw}); err != nil {
		r.registryFailed.Store(true)
		return err
	}
	r.registryRecords[row.Spec.Key()] = row
	return nil
}

func (r *Runtime) openRegistryOwners() error {
	r.registryRecords = map[string]registryOwnerRecord{}
	r.registrySessions = map[string]*registrySession{}
	if _, err := rand.Read(r.registryBoot[:]); err != nil {
		return err
	}
	rows, err := r.reports.ScanBounded(registryOwnerPrefix, 128, 16<<20)
	if err != nil {
		return err
	}
	for key, raw := range rows {
		row, err := schema.Decode[registryOwnerRecord](raw)
		if err != nil || row.Schema != 1 || row.Cluster != r.controlPolicy.Cluster || row.Owner != r.Identity.Public || row.DataOwner == ([32]byte{}) || row.Spec.Validate(row.Cluster) != nil || key != registryRecordKey(row.Spec.Tenant, row.Spec.ID) || row.Generation == 0 || row.SpecRevision == 0 || row.Native.Verify() != nil || row.Native.Spec.Scope != row.Spec.Volume || row.Native.Owner.Key != row.Owner {
			return registry.ErrStorage
		}
		switch row.Phase {
		case "intent", "reserved", "opening", "serving", "quiesced", "closing", "closed":
		default:
			return registry.ErrStorage
		}
		if row.Phase != "intent" && (row.Run == nil || row.Run.Spec != row.Spec || row.Run.Generation != row.Generation || row.Run.SpecRevision != row.SpecRevision || row.Run.Owner != row.Owner || row.Run.Consumer.Owner != row.Native.Owner || row.Run.DefinitionDigest == ([32]byte{}) || row.Run.OriginDigest == ([32]byte{})) {
			return registry.ErrStorage
		}
		if row.Pin != nil && (row.Pin.Key != volumes.NativeKey(row.Native.Spec) || row.Pin.Scope != row.Spec.Volume || row.Pin.Owner != row.Native.Owner || row.Pin.Consumer != registryNativeConsumer(row) || row.Pin.Pin.Generation != row.Native.Generation || row.Pin.Pin.Token == 0) {
			return registry.ErrStorage
		}
		if row.Pin != nil && !row.PinAttempted || row.Phase == "serving" && !row.KnownData {
			return registry.ErrStorage
		}
		if row.PinReturned && !row.IOClosed || row.IOClosed && row.Phase != "closing" && row.Phase != "closed" || row.Phase == "closed" && (!row.IOClosed || !row.PinReturned) {
			return registry.ErrStorage
		}
		r.registryRecords[row.Spec.Key()] = row
	}
	return nil
}

func (r *Runtime) registryWork(ctx context.Context, tenant, id string) (control.RegistryWork, error) {
	raw, _ := json.Marshal(control.RegistryWorkRequest{RegistrySelection: control.RegistrySelection{Tenant: tenant, ID: id}, At: time.Now().Unix()})
	reply, err := r.appCall(ctx, "registry-work", raw)
	if err != nil || reply.Local {
		log.Printf("registry %s/%s: registry-work not answered by the leader (local=%v): %v", tenant, id, reply.Local, err)
		return control.RegistryWork{}, registry.ErrUnavailable
	}
	work, err := schema.Decode[control.RegistryWork](reply.Data)
	if err != nil || work.Entry.Spec.Tenant != tenant || work.Entry.Spec.ID != id || work.Index == 0 || work.Epoch == 0 {
		log.Printf("registry %s/%s: registry-work reply invalid: %v", tenant, id, err)
		return control.RegistryWork{}, registry.ErrUnavailable
	}
	return work, nil
}

func (r *Runtime) reportRegistry(ctx context.Context, work control.RegistryWork, action string, observe *control.RegistryObservation, gone *volumes.Gone, budget *tenancy.ReservationClosure) error {
	generation, revision := work.Entry.Generation+1, work.Entry.Revision
	if active := work.Entry.Active; active != nil {
		generation, revision = active.Generation, active.SpecRevision
	}
	report := control.RegistryReport{Schema: 1, Cluster: r.controlPolicy.Cluster, Reporter: r.commandIdentity().Public, Tenant: work.Entry.Spec.Tenant, ID: work.Entry.Spec.ID, Action: action, Generation: generation, SpecRevision: revision, Epoch: work.Epoch, RootRevision: work.RootRevision, Index: work.Index, At: time.Now().Unix(), Observation: observe, Gone: gone, Budget: budget}
	if report.Observation != nil {
		report.Observation.At = report.At
	}
	report.Signature = ed25519.Sign(r.commandIdentity().Private, control.RegistryReportBytes(report))
	raw, _ := json.Marshal(report)
	reply, err := r.appCall(ctx, "registry-report", raw)
	if err != nil {
		return err
	}
	if reply.Committed == nil || reply.Committed.Result.Code != state.Applied {
		code := "no committed result"
		if reply.Committed != nil {
			code = fmt.Sprint(reply.Committed.Result.Code)
		}
		log.Printf("registry %s/%s: %s report refused: %s", work.Entry.Spec.Tenant, work.Entry.Spec.ID, action, code)
		return registry.ErrUnavailable
	}
	return nil
}

// registryBlocked remembers the last start refusal logged per registry, so
// an unchanged reason is logged once rather than every pass.
var registryBlocked sync.Map

func logRegistryBlocked(key, reason string) {
	if old, ok := registryBlocked.Load(key); ok && old == reason {
		return
	}
	registryBlocked.Store(key, reason)
	if reason != "" {
		log.Printf("registry %s: not started: %s", key, reason)
	}
}

// Quiescing joins live I/O but retains the local/shared writer for the SAME run.
// Authority loss or a daemon restart does not create a fresh run/upload ID.
func (r *Runtime) quiesceRegistry(ctx context.Context, row registryOwnerRecord) (registryOwnerRecord, error) {
	if live := r.registrySessions[row.Spec.Key()]; live != nil {
		if live.server != nil {
			if err := live.server.Close(ctx); err != nil {
				return row, err
			}
			live.server = nil
		}
		if live.store != nil {
			if err := live.store.Close(); err != nil {
				return row, err
			}
			live.store = nil
		}
		if live.directory != nil {
			if err := live.directory.Close(); err != nil {
				return row, err
			}
			live.directory = nil
		}
		delete(r.registrySessions, row.Spec.Key())
	}
	if row.Phase != "closing" && row.Phase != "closed" {
		row.Phase = "quiesced"
	}
	return row, r.saveRegistry(row)
}

func (r *Runtime) registryPin(ctx context.Context, row registryOwnerRecord) (registryOwnerRecord, error) {
	key, consumer := volumes.NativeKey(row.Native.Spec), registryNativeConsumer(row)
	native, err := r.nativeVolumes.View(key)
	if err != nil {
		return row, err
	}
	if row.Pin != nil {
		if native.Consumers[consumer] != row.Pin.Pin {
			return row, registry.ErrStorage
		}
		return row, nil
	}
	pin, exists := native.Consumers[consumer]
	if !exists {
		if !row.PinAttempted {
			row.PinAttempted = true
			if err = r.saveRegistry(row); err != nil {
				return row, err
			}
		}
		var borrowed volumes.NativeLease
		borrowed, err = r.nativeVolumes.Pin(ctx, key, consumer, row.Native.Generation)
		if err != nil && borrowed.Pin.Token == 0 {
			r.registryFailed.Store(true)
			return row, err
		}
		// Borrow may have committed before its subsequent native inspection
		// failed. Recover that exact consumer rather than allocate another pin.
		native, readErr := r.nativeVolumes.View(key)
		if readErr != nil {
			return row, errors.Join(err, readErr)
		}
		pin, exists = native.Consumers[consumer]
		if !exists {
			return row, errors.Join(registry.ErrStorage, err)
		}
	}
	row.Pin = &volumes.NativeLease{Key: key, Consumer: consumer, Scope: row.Spec.Volume, Owner: row.Native.Owner, Pin: pin}
	if saveErr := r.saveRegistry(row); saveErr != nil {
		return row, saveErr
	}
	return row, err
}

func (r *Runtime) openRegistryStore(ctx context.Context, row registryOwnerRecord, recovery bool) (registryOwnerRecord, error) {
	if row.Run == nil || row.IOClosed || row.PinReturned {
		return row, registry.ErrStorage
	}
	if recovery && (!row.KnownData || row.Pin == nil || !row.PinAttempted || row.Pin.Pin.Token == 0 || row.Phase == "closing" || row.Phase == "closed") {
		return row, registry.ErrStorage
	}
	if r.nativeVolumes == nil {
		return row, registry.ErrUnavailable
	}
	if !recovery && row.Phase != "opening" {
		row.Phase = "opening"
		if err := r.saveRegistry(row); err != nil {
			return row, err
		}
	}
	row, err := r.registryPin(ctx, row)
	if err != nil {
		return row, err
	}
	live := r.registrySessions[row.Spec.Key()]
	if live == nil {
		live = &registrySession{}
		r.registrySessions[row.Spec.Key()] = live
	}
	if live.directory == nil {
		live.directory, err = r.nativeVolumes.OpenDataDirectory(ctx, *row.Pin)
		if err != nil {
			return row, err
		}
	}
	if live.store == nil {
		root := live.directory.Root
		info, err := root.Lstat("registry")
		if os.IsNotExist(err) && !row.KnownData {
			if err = root.Mkdir("registry", 0700); err != nil {
				return row, err
			}
			parent, e := root.Open(".")
			if e != nil {
				return row, e
			}
			err = parent.Sync()
			closed := parent.Close()
			if err != nil || closed != nil {
				return row, errors.Join(err, closed)
			}
			info, err = root.Lstat("registry")
		}
		if err != nil || !info.IsDir() {
			return row, registry.ErrStorage
		}
		if row.KnownData {
			dbInfo, e := root.Lstat("registry/registry.db")
			if e != nil || recovery && (!dbInfo.Mode().IsRegular() || dbInfo.Size() == 0) {
				return row, registry.ErrStorage
			}
		}
		if err = live.directory.Check(); err != nil {
			return row, err
		}
		live.store, err = registry.OpenStore(ctx, filepath.Join(live.directory.Path(), "registry"), registry.Scope{Schema: 1, Cluster: row.Cluster, Node: row.DataOwner, Tenant: row.Spec.Tenant, Registry: row.Spec.ID}, row.Spec.Metadata, row.Spec.Blobs)
		if err != nil {
			return row, err
		}
		if err = live.directory.Check(); err != nil {
			return row, err
		}
		// This durable floor precedes the first possible HTTPS request. Every
		// later run or unclean reopen must retain the original root and DB.
		row.KnownData = true
		if err = r.saveRegistry(row); err != nil {
			return row, err
		}
	}
	return row, nil
}

func (r *Runtime) startRegistry(ctx context.Context, row registryOwnerRecord) (registryOwnerRecord, error) {
	row, err := r.openRegistryStore(ctx, row, false)
	if err != nil {
		return row, err
	}
	live := r.registrySessions[row.Spec.Key()]
	if live.server == nil {
		if _, _, err = r.registryCurrent(ctx, *row.Run); err != nil {
			return row, err
		}
		handler, err := live.store.Handler(ctx, log.New(os.Stderr, "registry ", log.LstdFlags))
		if err != nil {
			return row, err
		}
		certificate, _, err := r.registryCertificate(ctx, row, [32]byte{})
		if err != nil {
			return row, err
		}
		live.server, err = registry.OpenServer(r.ctx, row.Cluster, row.Spec, certificate.Certificate, handler, r.registryAuthorization(*row.Run, live.store), log.New(os.Stderr, "registry ", log.LstdFlags))
		if err != nil {
			return row, err
		}
	}
	row.Phase = "serving"
	return row, r.saveRegistry(row)
}

func (r *Runtime) closeRegistryRun(ctx context.Context, work control.RegistryWork, row registryOwnerRecord) error {
	if row.Run == nil || work.Entry.Active == nil {
		return registry.ErrStorage
	}
	view, err := r.Engine().ReadAtLeast(ctx, work.Index)
	if err != nil {
		return err
	}
	builds, err := r.controlPolicy.RegistryImageBuildsPending(view.State, *row.Run)
	if err != nil {
		return err
	}
	if builds {
		// New HTTP work is stopped immediately, while the original accepted
		// build can still settle its already sent root through the owner read.
		if live := r.registrySessions[row.Spec.Key()]; live != nil && live.server != nil {
			if err := live.server.Close(ctx); err != nil {
				return err
			}
			live.server = nil
		}
		if row.KnownData && row.Pin != nil {
			row, err = r.openRegistryStore(ctx, row, true)
			if err != nil {
				return err
			}
		}
		row.Phase = "quiesced"
		return r.saveRegistry(row)
	}
	// Commit the shared drain before returning the native pin. The same FSM
	// excludes a concurrent maintenance acceptance; physical close is its later
	// positive proof, never its admission fence.
	if !work.Entry.Active.Draining {
		view, err := r.Engine().ReadAtLeast(ctx, work.Index)
		if err != nil {
			return err
		}
		held, err := r.controlPolicy.RegistryMaintenancePending(view.State, row.Spec.Tenant, row.Spec.ID)
		if err != nil {
			return err
		}
		if held {
			if live := r.registrySessions[row.Spec.Key()]; live != nil && live.server != nil {
				if err = live.server.Close(ctx); err != nil {
					return err
				}
				live.server = nil
			}
			return nil // keep the original Store/pin for authorized original cleanup
		}
		return r.reportRegistry(ctx, work, "drain", nil, nil, nil)
	}
	row.Phase = "closing"
	if err := r.saveRegistry(row); err != nil {
		return err
	}
	row, err = r.quiesceRegistry(ctx, row)
	if err != nil {
		return err
	}
	row.IOClosed = true
	if err = r.saveRegistry(row); err != nil {
		return err
	}
	if !row.PinReturned {
		if row.Pin == nil && row.PinAttempted {
			native, e := r.nativeVolumes.View(volumes.NativeKey(row.Native.Spec))
			if e != nil {
				return e
			}
			if pin, exists := native.Consumers[registryNativeConsumer(row)]; exists {
				row.Pin = &volumes.NativeLease{Key: volumes.NativeKey(row.Native.Spec), Consumer: registryNativeConsumer(row), Scope: row.Spec.Volume, Owner: row.Native.Owner, Pin: pin}
				if err = r.saveRegistry(row); err != nil {
					return err
				}
			}
		}
		if row.Pin != nil {
			if err = r.nativeVolumes.Return(*row.Pin); err != nil {
				r.registryFailed.Store(true)
				return err
			}
		}
		row.PinReturned = true
		if err = r.saveRegistry(row); err != nil {
			return err
		}
	}
	run := work.Entry.Active
	gone := volumes.Gone{Scope: row.Spec.Volume, Consumer: run.Consumer, Stopped: true, MountsGone: true}
	gone.Signature = ed25519.Sign(r.Identity.Private, volumes.GoneBytes(gone))
	proof := tenancy.ReservationClosure{Schema: 1, Cluster: row.Cluster, Key: run.Budget.Key, Node: run.Spec.Node, Owner: run.Owner, Generation: run.Budget.Generation, DrainRevision: run.Budget.Revision, NativeGone: true}
	proof.Signature = ed25519.Sign(r.Identity.Private, tenancy.ReservationClosureBytes(proof))
	if err = r.reportRegistry(ctx, work, "closed", nil, &gone, &proof); err != nil {
		return err
	}
	row.Phase = "closed"
	return r.saveRegistry(row)
}

func (r *Runtime) reconcileRegistries(ctx context.Context, v cluster.View) error {
	r.registryMu.Lock()
	defer r.registryMu.Unlock()
	if r.registryRecords == nil {
		return nil
	}
	if r.registryFailed.Load() {
		return registry.ErrStorage
	}
	book, err := r.controlPolicy.Registries(v.State)
	if err != nil {
		return err
	}
	var failed error
	for _, entry := range book.Entries() {
		key := entry.Spec.Key()
		row, local := r.registryRecords[key]
		if entry.Spec.Node != r.installation.record.Root.Self.ID && (entry.Active == nil || entry.Active.Owner != r.Identity.Public) && !local {
			continue
		}
		work, err := r.registryWork(ctx, entry.Spec.Tenant, entry.Spec.ID)
		if err != nil {
			if local && row.Run != nil && row.Phase != "closed" {
				_, err = r.quiesceRegistry(ctx, row)
				if err != nil {
					failed = errors.Join(failed, err)
				}
			}
			failed = errors.Join(failed, registry.ErrUnavailable)
			continue
		}
		if work.Entry.Active == nil {
			if local && row.Run != nil && row.Phase != "closed" {
				closed := work.Entry.Closed
				if closed == nil || closed.Run.Generation != row.Generation || !row.IOClosed || !row.PinReturned {
					failed = errors.Join(failed, registry.ErrStorage)
					continue
				}
				row.Phase = "closed"
				if err = r.saveRegistry(row); err != nil {
					failed = errors.Join(failed, err)
					continue
				}
			}
			logRegistryBlocked(key, work.Blocked)
			if !work.MayStart || local && row.Phase == "closed" && row.SpecRevision >= work.Entry.Revision {
				continue
			}
			if r.nativeVolumes == nil || work.Native == nil {
				log.Printf("registry %s: cannot reserve: workload volumes on this server %v, leader volume record %v", key, r.nativeVolumes != nil, work.Native != nil)
				failed = errors.Join(failed, registry.ErrUnavailable)
				continue
			}
			if !local || row.Phase == "closed" || row.Phase == "intent" && row.SpecRevision != work.Entry.Revision {
				if !local && work.Entry.Generation > 0 && work.Entry.Closed != nil && work.Entry.Closed.Run.Owner == r.Identity.Public {
					failed = errors.Join(failed, registry.ErrStorage)
					continue
				}
				known := row.KnownData || work.Entry.DataOwner != r.Identity.Public || work.Entry.Generation > 0
				row = registryOwnerRecord{Schema: 1, Cluster: r.controlPolicy.Cluster, Owner: r.Identity.Public, DataOwner: work.Entry.DataOwner, Spec: work.Entry.Spec, SpecRevision: work.Entry.Revision, Generation: work.Entry.Generation + 1, Native: *work.Native, Phase: "intent", KnownData: known}
				if err = r.saveRegistry(row); err != nil {
					failed = errors.Join(failed, err)
					continue
				}
			}
			if row.Phase != "intent" || row.Generation != work.Entry.Generation+1 || row.Spec != work.Entry.Spec {
				failed = errors.Join(failed, registry.ErrStorage)
				continue
			}
			if err = r.reportRegistry(ctx, work, "reserve", nil, nil, nil); err != nil {
				failed = errors.Join(failed, err)
			}
			continue
		}
		if work.Entry.Active.Owner != r.Identity.Public {
			continue
		}
		if r.nativeVolumes == nil {
			log.Printf("registry %s: this server has no workload volumes", key)
			failed = errors.Join(failed, registry.ErrUnavailable)
			continue
		}
		if !local || row.Generation != work.Entry.Active.Generation || row.Spec != work.Entry.Active.Spec || row.DataOwner != work.Entry.DataOwner {
			failed = errors.Join(failed, registry.ErrStorage)
			continue
		}
		if row.Run == nil {
			run := *work.Entry.Active
			row.Run = &run
			row.Phase = "reserved"
			if err = r.saveRegistry(row); err != nil {
				failed = errors.Join(failed, err)
				continue
			}
		}
		if !work.MayStart || work.Entry.Active.Draining || row.Phase == "closing" || row.Phase == "closed" {
			if err = r.closeRegistryRun(ctx, work, row); err != nil {
				failed = errors.Join(failed, err)
			}
			continue
		}
		live := r.registrySessions[key]
		if live != nil && live.server != nil && live.server.Error() != nil {
			_, err = r.quiesceRegistry(ctx, row)
			failed = errors.Join(failed, err)
			continue
		}
		if live == nil || live.server == nil {
			row, err = r.startRegistry(ctx, row)
			if err != nil {
				failed = errors.Join(failed, fmt.Errorf("registry %s: %w", key, err))
				continue
			}
		}
		live = r.registrySessions[key]
		// A renewed store certificate replaces the served pair; a host left
		// without one (removed domain, disabled certificate) stops the run.
		if next, changed, err := r.registryCertificate(ctx, row, live.server.Certificate()); errors.Is(err, ingress.ErrCertificateWithdrawn) {
			_, err = r.quiesceRegistry(ctx, row)
			failed = errors.Join(failed, fmt.Errorf("registry %s: %w", key, ingress.ErrCertificateWithdrawn), err)
			continue
		} else if err != nil {
			failed = errors.Join(failed, fmt.Errorf("registry %s: %w", key, err))
		} else if changed {
			if err = live.server.SetCertificate(next.Certificate); err != nil {
				failed = errors.Join(failed, fmt.Errorf("registry %s: %w", key, err))
			}
		}
		ready := work.Entry.Active.Ready
		if ready == nil || ready.Boot != r.registryBoot || ready.Certificate != live.server.Certificate() {
			if err = r.reportRegistry(ctx, work, "serving", &control.RegistryObservation{Boot: r.registryBoot, Certificate: live.server.Certificate()}, nil, nil); err != nil {
				failed = errors.Join(failed, err)
			}
		}
	}
	return failed
}

func (r *Runtime) closeRegistryOwners(ctx context.Context) error {
	r.registryMu.Lock()
	defer r.registryMu.Unlock()
	var result error
	for key := range r.registrySessions {
		row, ok := r.registryRecords[key]
		if !ok {
			result = errors.Join(result, registry.ErrStorage)
			continue
		}
		_, err := r.quiesceRegistry(ctx, row)
		result = errors.Join(result, err)
	}
	return result
}
