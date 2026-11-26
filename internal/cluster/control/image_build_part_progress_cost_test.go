// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/imagebuild"
)

// Select either subtest for a finite CPU profile at the same admission,
// reducer/FSM and before/after permit boundary. The original fixture takes
// *testing.T, so this is a test rather than a separate benchmark fixture.
// Receipts are injected by buildPartProgress: no ZIP, Raft or fsync cost is
// measured, and the shared part bytes do not allocate an entire ZIP fixture.
func TestImageBuildPartProgressFiniteCoreCost(t *testing.T) {
	for _, parts := range []int{300, 3052} {
		t.Run(fmt.Sprintf("%dparts", parts), func(t *testing.T) {
			f, _ := imageBuildFixture(t)
			data := bytes.Repeat([]byte{17}, imagebuild.PartBytes)
			started := time.Now()
			f.apply("manager", "begin-build-zip-upload", 0, ImageBuildUploadBegin{Tenant: "tenant", Context: "source", Upload: "finite-core", Length: int64(parts * len(data)), Digest: sha256.Sum256([]byte("whole injected ZIP for finite core cost")), ExpiresAt: 1000}, state.Applied)
			builds, err := f.p.ImageBuilds(f.s)
			if err != nil {
				t.Fatal(err)
			}
			begin, found := builds.Upload("tenant", "finite-core")
			if !found || begin.Received != 0 || begin.Revision != 1 {
				t.Fatal("finite core cost lost original begin")
			}
			encoded, err := state.Encode(f.s)
			if err != nil {
				t.Fatal(err)
			}
			userReceipts := buildProgressUserReceipts(t, encoded)
			for index := range parts {
				report, call := buildPartProgress(t, f, "finite-core", uint32(index), data)
				before, err := f.p.ImageBuildIOPermit(f.s, report.Owner, call)
				if err != nil || before.Recorded || before.Scope != begin.Scope || before.Expected != uint64(index+1) {
					t.Fatal("finite core cost new part permit", index, err)
				}
				applyBuildPartProgress(t, f, report, state.Applied)
				after, err := f.p.ImageBuildIOPermit(f.s, report.Owner, call)
				if err != nil || !after.Recorded || after.Scope != begin.Scope || after.Expected != uint64(index+2) {
					t.Fatal("finite core cost original ACK permit", index, err)
				}
			}
			elapsed := time.Since(started)
			builds, err = f.p.ImageBuilds(f.s)
			if err != nil {
				t.Fatal(err)
			}
			upload, found := builds.Upload("tenant", "finite-core")
			if !found || upload.Scope != begin.Scope || !buildJSONEqual(upload.Begin, begin.Begin) || !buildJSONEqual(upload.Origin, begin.Origin) || upload.Received != uint32(parts) || upload.Revision != uint64(parts+1) || upload.Progress == nil || f.s.ModuleEpoch() != begin.Begin.Epoch {
				t.Fatal("finite core cost changed original scope/begin/origin or lost received parts")
			}
			encoded, err = state.Encode(f.s)
			if err != nil || !bytes.Equal(buildProgressUserReceipts(t, encoded), userReceipts) {
				t.Fatal("finite core cost owner reports changed original user ledger", err)
			}
			t.Logf("injected-receipt core: begin + %d before-permit/report-apply/after-permit parts in %s; excludes native ZIP/Raft/fsync", parts, elapsed)
		})
	}
}
