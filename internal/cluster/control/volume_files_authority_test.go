// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
)

func TestVolumeFileWorkRechecksCurrentAuthorityWithoutReturningOriginalWriter(t *testing.T) {
	f := newBackupCore(t)
	q := VolumeFileChange{Scope: f.scope, Path: "backups/original.bin", Size: 1, MaxBytes: 1024, Digest: sha256.Sum256([]byte{1})}
	f.apply("original-file", "volume-file-put", f.core().Revision(), q, state.Applied)
	jobs := f.view().VolumeFiles()
	if len(jobs) != 1 {
		t.Fatal("original file job missing")
	}
	job := jobs[0]
	if current, err := f.p.VolumeFileWork(f.s, job.Native.Owner.Key, f.session, job.ID, 3); err != nil || current.ID != job.ID || current.Consumer != job.Consumer {
		t.Fatal("current exact owner could not consume original", err)
	}
	if _, err := f.p.VolumeFileWork(f.s, [32]byte{99}, f.session, job.ID, 3); err == nil {
		t.Fatal("different native owner admitted")
	}
	if _, err := f.p.VolumeFileWork(f.s, job.Native.Owner.Key, f.session, "another-original", 3); err == nil {
		t.Fatal("different operation admitted")
	}
	catalog, _ := f.p.Catalog(f.s)
	u, _ := catalog.User("admin")
	u.Username = "account-revision-changed"
	expected := u.Revision
	u.Revision = 0 // put-user carries expected CAS separately from replacement input.
	f.apply("change-original-user", "put-user", expected, accountFields(u), state.Applied)
	if _, err := f.p.VolumeFileWork(f.s, job.Native.Owner.Key, f.session, job.ID, 3); err == nil {
		t.Fatal("old user revision authorized further file I/O")
	}
	// Revoking future consumption does not manufacture a native close or
	// replace the accepted operation. Its writer remains until signed Gone.
	saved, ok := f.view().VolumeFile(job.ID)
	if !ok || saved.Phase != "Reserved" || saved.Consumer != job.Consumer || saved.Origin.RequestID != job.Origin.RequestID || len(f.core().Consumers()) != 1 {
		t.Fatal("current authority loss discarded original writer or provenance")
	}
}
