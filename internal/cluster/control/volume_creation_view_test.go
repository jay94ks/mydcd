// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
)

func TestVolumeCreatingViewIsNotNativeReadinessAndRedactsAcceptedSession(t *testing.T) {
	f, q := createCore(t)
	f.apply("reserve-view", "begin-volume-create", 0, q, state.Applied)
	c, _ := f.p.Catalog(f.s)
	rows, next, err := f.view().Page(c, "admin", "tenant", "")
	if err != nil || next != "" || len(rows) != 2 {
		t.Fatal("pending creation page", rows, err)
	}
	var found bool
	for _, row := range rows {
		if row.Scope == q.Scope {
			found = true
			if row.Phase != "Reserved" || row.Owner.Native != "" || row.CreateRevision != 1 || row.Consumers != 0 {
				t.Fatal("creating view claimed native readiness", row)
			}
		}
	}
	if !found {
		t.Fatal("pending creation missing")
	}
	raw, _ := json.Marshal(rows)
	for _, secret := range []string{"Origin", "Session", "Signature", "Materialization", f.session.ID} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("private creation metadata leaked", secret)
		}
	}
	if _, err := f.p.VolumeNative(f.s, f.session, 2, "tenant", VolumeSelector{App: "app", ID: "created"}); err == nil {
		t.Fatal("pending creation supplied native identity")
	}
}
