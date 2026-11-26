// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// These use real private metadata files and current namespace observations,
// but perform no mount. Actual source/mount/Docker boundaries are separate.
func TestFixedProjectionStageRejectsForeignPathAndPreservesUnknownFiles(t *testing.T) {
	ready, private := fixedReadyFixture(t)
	p, err := openPrivateProjection(filepath.Join(t.TempDir(), "mounts"), private)
	if err != nil {
		t.Fatal(err)
	}
	defer p.file.Close()
	name := FixedNativeName(ready.Spec.Scope)
	if err = unix.Mkdirat(int(p.file.Fd()), name, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err = p.stage(ready.Spec); err == nil {
		t.Fatal("foreign final slot adopted")
	}
	if err = p.recoverStaging(ready.Spec); err == nil {
		t.Fatal("foreign final slot removed")
	}
	if err = unix.Unlinkat(int(p.file.Fd()), name, unix.AT_REMOVEDIR); err != nil {
		t.Fatal(err)
	}
	owner, err := p.stage(ready.Spec)
	if err != nil {
		t.Fatal(err)
	}
	if owner.Spec != projectionSpec(ready.Spec) {
		t.Fatal("owner not bound to declaration")
	}
	foreign := filepath.Join(p.path, name, "foreign")
	if err = os.WriteFile(foreign, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = p.recoverStaging(ready.Spec); err == nil {
		t.Fatal("unknown native metadata deleted")
	}
	if raw, err := os.ReadFile(foreign); err != nil || string(raw) != "preserve" {
		t.Fatal("unknown data changed", err)
	}
	if err = os.Remove(foreign); err != nil {
		t.Fatal(err)
	} // fixture removes only its own injected file
	if err = p.recoverStaging(ready.Spec); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(p.path, name)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("pre-checkpoint staging not fully removed", err)
	}
}

func TestFixedProjectionEpochSignatureAndSameBootNamespaceFence(t *testing.T) {
	ready, private := fixedReadyFixture(t)
	p, err := openPrivateProjection(filepath.Join(t.TempDir(), "mounts"), private)
	if err != nil {
		t.Fatal(err)
	}
	defer p.file.Close()
	owner, err := p.stage(ready.Spec)
	if err != nil {
		t.Fatal(err)
	}
	slot, err := openProjectionChild(int(p.file.Fd()), FixedNativeName(ready.Spec.Scope))
	if err != nil {
		t.Fatal(err)
	}
	epoch, err := p.readProjectionEpoch(slot)
	if err != nil {
		_ = slot.Close()
		t.Fatal(err)
	}
	wrong := epoch
	wrong.Namespace[0] ^= 1
	if err = p.writeProjectionEpoch(slot, wrong); err != nil {
		_ = slot.Close()
		t.Fatal(err)
	}
	if err = p.pinProjectionEpoch(slot, owner.Spec, true); err == nil {
		_ = slot.Close()
		t.Fatal("same current boot switched ownership namespace")
	}
	if err = p.recoverStaging(ready.Spec); err == nil {
		_ = slot.Close()
		t.Fatal("different namespace inferred native closure")
	}
	if err = p.writeProjectionEpoch(slot, epoch); err != nil {
		_ = slot.Close()
		t.Fatal(err)
	}
	corrupt := epoch
	corrupt.Boot[0] ^= 1
	raw, _ := json.Marshal(corrupt) // preserve the OLD signature: corruption is not a new node observation
	if err = os.WriteFile(filepath.Join(p.path, FixedNativeName(ready.Spec.Scope), "epoch.json"), raw, 0600); err != nil {
		_ = slot.Close()
		t.Fatal(err)
	}
	if err = p.pinProjectionEpoch(slot, owner.Spec, true); err == nil {
		_ = slot.Close()
		t.Fatal("corrupt boot fact permitted namespace migration")
	}
	if err = p.writeProjectionEpoch(slot, epoch); err != nil {
		_ = slot.Close()
		t.Fatal(err)
	}
	_ = slot.Close()
	if err = p.recoverStaging(ready.Spec); err != nil {
		t.Fatal(err)
	}
}
