// SPDX-License-Identifier: Apache-2.0

package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jay94ks/seafield/internal/storage"
	"os"
	"path/filepath"
	"testing"
)

// Files are actual effects here. This adapter is only a test consumer of the
// product journal; it does not stand in for Docker or kernel verification.
type fileDriver struct {
	path                    string
	j                       *Journal
	t                       *testing.T
	executions, inspections int
	loseReply               bool
}

func (d *fileDriver) Execute(_ context.Context, key string, op Operation) (Outcome, error) {
	d.executions++
	b, err := d.j.db.Get("resource/" + key)
	var r Record
	if err != nil || json.Unmarshal(b, &r) != nil || r.State.Pending == nil || *r.State.Pending != op || op.Phase != Dispatched {
		d.t.Fatal("effect preceded durable dispatch", err)
	}
	if op.Kind == Remove {
		err = os.Remove(d.path)
	} else {
		err = os.WriteFile(d.path, []byte(op.Target.Spec), 0600)
	}
	if err != nil {
		return EffectUnknown, err
	}
	if d.loseReply {
		return EffectApplied, errors.New("effect completed; reply lost")
	}
	return EffectApplied, nil
}
func (d *fileDriver) Recover(_ context.Context, _ string, op Operation) (Outcome, error) {
	d.inspections++
	b, err := os.ReadFile(d.path)
	if op.Kind == Remove && errors.Is(err, os.ErrNotExist) {
		return EffectApplied, nil
	}
	if err == nil && op.Kind == Apply && string(b) == op.Target.Spec {
		return EffectApplied, nil
	}
	// A momentarily absent file does not prove an asynchronous operation ended.
	return EffectUnknown, nil
}

func TestRealBoundaryJournalRestartAndDurableConsumers(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	path := filepath.Join(root, "module.db")
	j, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = j.Close() }()
	driver := &fileDriver{path: filepath.Join(root, "effect"), j: j, t: t, loseReply: true}
	first := Desired{Revision: 1, Resource: Resource{Generation: 1, Spec: "original", Present: true}}
	if err = j.Desired("bridge", first, 2); err != nil {
		t.Fatal(err)
	}
	if err = j.Step(ctx, "bridge", driver); err == nil {
		t.Fatal("lost reply claimed success")
	}
	r, _ := j.Read("bridge")
	if r.State.Pending == nil || r.State.Pending.Phase != RecoveryRequired || r.State.Applied.Present {
		t.Fatal("unknown effect forgotten", r)
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	j, err = OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	driver.j = j
	driver.loseReply = false
	if err = j.Step(ctx, "bridge", driver); err != nil {
		t.Fatal(err)
	}
	if driver.executions != 1 || driver.inspections != 1 {
		t.Fatal("restarted operation was repeated", driver.executions, driver.inspections)
	}
	pin, err := j.Borrow("bridge", "workload/container-1", 1)
	if err != nil {
		t.Fatal(err)
	}
	again, err := j.Borrow("bridge", "workload/container-1", 1)
	if err != nil || again != pin {
		t.Fatal("consumer borrow not idempotent", err)
	}
	second := Desired{Revision: 2, Resource: Resource{Generation: 2, Spec: "replacement", Present: true}}
	if err = j.Desired("bridge", second, 2); err != nil {
		t.Fatal(err)
	}
	if err = j.Step(ctx, "bridge", driver); !errors.Is(err, ErrPending) {
		t.Fatal("removed resource with a live consumer", err)
	}
	if _, err = j.Borrow("bridge", "ingress/request-1", 1); !errors.Is(err, ErrLease) {
		t.Fatal("new consumer entered drain", err)
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	j, err = OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	driver.j = j
	r, _ = j.Read("bridge")
	if len(r.Consumers) != 1 || !r.Pins.Draining {
		t.Fatal("restart dropped a consumer or drain", r)
	}
	if err = j.Return("bridge", "wrong-owner", pin); !errors.Is(err, ErrLease) {
		t.Fatal("foreign consumer returned pin", err)
	}
	if err = j.Return("bridge", "workload/container-1", pin); err != nil {
		t.Fatal(err)
	}
	if err = j.Step(ctx, "bridge", driver); err != nil {
		t.Fatal(err)
	} // remove gen 1
	if err = j.Step(ctx, "bridge", driver); err != nil {
		t.Fatal(err)
	} // apply gen 2
	newPin, err := j.Borrow("bridge", "workload/container-1", 2)
	if err != nil || newPin.Token <= pin.Token {
		t.Fatal("new generation reused token", err)
	}
	if err = j.Return("bridge", "workload/container-1", pin); !errors.Is(err, ErrLease) {
		t.Fatal("stale completion returned new pin", err)
	}
	if err = j.Return("bridge", "workload/container-1", newPin); err != nil {
		t.Fatal(err)
	}
	r, _ = j.Read("bridge")
	r.Consumers["forged"] = pin
	r.State.Desired.Spec = "forged"
	r2, _ := j.Read("bridge")
	if len(r2.Consumers) != 0 || r2.State.Desired.Spec != "replacement" {
		t.Fatal("published record aliases caller")
	}
	t.Logf("real sync DB/reopen; original dispatch executes once; inspect=%d; drain retains consumer; replacement rejects stale token", driver.inspections)
}

func TestRealBoundaryJournalWriteFailureDoesNotPublish(t *testing.T) {
	path := filepath.Join(t.TempDir(), "module.db")
	j, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	driver := &fileDriver{path: filepath.Join(t.TempDir(), "effect"), j: j, t: t}
	d := Desired{Revision: 1, Resource: Resource{Generation: 1, Spec: "one", Present: true}}
	if err = j.Desired("tun", d, 1); err != nil {
		t.Fatal(err)
	}
	if err = j.Step(context.Background(), "tun", driver); err != nil {
		t.Fatal(err)
	}
	before, _ := j.Read("tun")
	if err = j.db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = j.Borrow("tun", "consumer", 1); err == nil {
		t.Fatal("borrow published despite DB failure")
	}
	if _, err = j.Read("tun"); !errors.Is(err, ErrJournalUncertain) {
		t.Fatal("uncertain journal remained readable", err)
	}
	_ = j.Close()
	j, err = OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	r, err := j.Read("tun")
	if err != nil || len(r.Consumers) != 0 || r.Pins.Next != before.Pins.Next {
		t.Fatal("failed borrow survived reopen", err)
	}
	if _, err = j.Read("absent"); !errors.Is(err, storage.ErrMissing) {
		t.Fatal(err)
	}
}

func TestRealBoundaryJournalUnknownAbsenceRetainsOriginal(t *testing.T) {
	j, err := OpenJournal(filepath.Join(t.TempDir(), "module.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	driver := &fileDriver{path: filepath.Join(t.TempDir(), "effect"), j: j, t: t, loseReply: true}
	if err = j.Desired("network", Desired{Revision: 1, Resource: Resource{Generation: 1, Spec: "old", Present: true}}, 1); err != nil {
		t.Fatal(err)
	}
	_ = j.Step(context.Background(), "network", driver)
	if err = os.Remove(driver.path); err != nil {
		t.Fatal(err)
	}
	if err = j.Desired("network", Desired{Revision: 2, Resource: Resource{Generation: 2, Spec: "new", Present: true}}, 1); err != nil {
		t.Fatal(err)
	}
	if err = j.Step(context.Background(), "network", driver); !errors.Is(err, ErrPending) {
		t.Fatal("absence treated as no effect", err)
	}
	r, _ := j.Read("network")
	if r.State.Pending == nil || r.State.Pending.ID != 1 || r.State.Pending.Target.Spec != "old" || driver.executions != 1 {
		t.Fatal("original operation replaced", r)
	}
}
