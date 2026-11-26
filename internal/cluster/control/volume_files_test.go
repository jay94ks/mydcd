// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
	"testing"
)

func TestVolumeFileUsesOriginalWriterReservationAndSignedClosureAfterUserChange(t *testing.T) {
	f := newBackupCore(t)
	body := []byte("file-content-outside-operation-history")
	q := VolumeFileChange{Scope: f.scope, Path: "mydc-web-backups/today.db", Size: int64(len(body)), MaxBytes: 1024, Digest: sha256.Sum256(body)}
	f.apply("put-original", "volume-file-put", f.core().Revision(), q, state.Applied)
	jobs := f.view().VolumeFiles()
	if len(jobs) != 1 {
		t.Fatal("original file job missing")
	}
	job := jobs[0]
	if job.Phase != "Reserved" || !job.Consumer.Writable || len(f.core().Consumers()) != 1 {
		t.Fatal("file bypassed shared writer reservation")
	}
	raw, _ := json.Marshal(job)
	if bytes.Contains(raw, body) {
		t.Fatal("file content entered shared history")
	}
	f.apply("competing-writer", "volume-file-put", f.core().Revision(), q, state.ConditionFailed)
	c, _ := f.p.Catalog(f.s)
	u, _ := c.User("admin")
	u.Credentials[0].Label = "new-account-revision"
	expected := u.Revision
	u.Revision = 0 // put-user carries expected CAS separately from replacement input.
	f.apply("account-change", "put-user", expected, u, state.Applied)
	gone := volumes.Gone{Scope: q.Scope, Consumer: job.Consumer, Stopped: true, MountsGone: true}
	gone.Signature = ed25519.Sign(f.node, volumes.GoneBytes(gone))
	report := VolumeFileReport{Schema: 1, Operation: "file", ID: job.ID, Code: "ok", Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(VolumesKey).Revision, At: 10, Result: &volumes.FileResult{Path: q.Path, Size: q.Size, Digest: q.Digest}, Gone: gone}
	report.Signature = ed25519.Sign(f.node, VolumeFileReportBytes(report))
	input, _ := json.Marshal(report)
	cmd, err := f.p.ResolveVolumeFileReport(f.s, job.Native.Owner.Key, input)
	if err != nil {
		t.Fatal(err)
	}
	applyRestartCore(t, f, cmd, state.Applied)
	if len(f.core().Consumers()) != 0 {
		t.Fatal("positive original close did not return writer")
	}
	applyRestartCore(t, f, cmd, state.Applied)
	raw, err = state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := state.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	book, err := f.p.Volumes(restored)
	if err != nil {
		t.Fatal(err)
	}
	saved, ok := book.VolumeFile(job.ID)
	if !ok || saved.Phase != "Completed" || saved.Origin.RequestID != job.Origin.RequestID || saved.Request != q {
		t.Fatal("snapshot replaced original file/native intent")
	}
}
