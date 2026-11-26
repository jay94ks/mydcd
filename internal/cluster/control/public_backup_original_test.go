// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
)

func TestPublicBackupLimitOriginalSurvivesReadModifyCASWithoutAuthorityAlias(t *testing.T) {
	f := newBackupCore(t)
	f.limits()
	// An existing legacy native needs its explicit capacity mapping before an Original policy can be enabled.
	mapOriginalCapacity(t, f, 64)
	query := PublicReadQuery{Node: "node-a"}
	read := func(tenant string, session access.Session) PublicBackupLimit {
		t.Helper()
		page, err := f.p.PublicRead(f.s, session, 10, "volume-backup-limits", tenant, query, "")
		if err != nil || len(page.Rows) != 1 || page.Rows[0].BackupLimit == nil {
			t.Fatal(page, err)
		}
		raw, err := json.Marshal(page)
		if err != nil {
			t.Fatal(err)
		}
		var decoded PublicReadPage
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		return *decoded.Rows[0].BackupLimit
	}
	payload := func(row PublicBackupLimit) VolumeBackupLimit {
		return VolumeBackupLimit{Tenant: row.Tenant, Node: row.Node, Bytes: row.Bytes + 1024, Count: row.Count, StagingBytes: row.StagingBytes, StagingCount: row.StagingCount, Original: row.Original}
	}
	for _, tenant := range []string{"", "tenant"} {
		old := read(tenant, f.session)
		raw, _ := json.Marshal(old)
		if old.Original != nil || bytes.Contains(raw, []byte(`"Original"`)) {
			t.Fatal("legacy absent policy changed", old)
		}
		limit := payload(old)
		limit.Original = &OriginalVolumeLimit{Bytes: 524288, Count: 4}
		f.apply("original-add-"+tenant, "set-volume-backup-limit", old.Revision, limit, state.Applied)
		row := read(tenant, f.session)
		if row.Original == nil || *row.Original != *limit.Original {
			t.Fatal("public original policy missing", row)
		}
		f.apply("original-roundtrip-"+tenant, "set-volume-backup-limit", row.Revision, payload(row), state.Applied)
		current := read(tenant, f.session)
		if current.Revision != row.Revision+1 || current.Bytes != row.Bytes+1024 || current.Original == nil || *current.Original != *limit.Original {
			t.Fatal("public read could not preserve original budget on CAS", current)
		}
		// An omitted policy still cannot erase an established original reservation.
		omitted := payload(current)
		omitted.Original = nil
		f.apply("original-omitted-"+tenant, "set-volume-backup-limit", current.Revision, omitted, state.ConditionFailed)
		// Rejection receipts advance state; compare the authoritative budget itself.
		fresh := read(tenant, f.session)
		if fresh.Revision != current.Revision || fresh.Original == nil || *fresh.Original != *limit.Original {
			t.Fatal("rejection changed original budget", fresh)
		}
		page, err := f.p.PublicRead(f.s, f.session, 10, "volume-backup-limits", tenant, query, "")
		if err != nil {
			t.Fatal(err)
		}
		page.Rows[0].BackupLimit.Original.Bytes = 1
		fresh = read(tenant, f.session)
		if fresh.Original.Bytes != limit.Original.Bytes {
			t.Fatal("returned pointer aliased authoritative policy")
		}
	}
	limited := f.session
	limited.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read}}}
	limited.Signature = ed25519.Sign(f.node, access.SessionBytes(limited))
	if row := read("tenant", limited); row.Original == nil || row.Original.Bytes != 524288 {
		t.Fatal("tenant Read did not include its own original policy", row)
	}
	for _, tenant := range []string{"", "foreign"} {
		if _, err := f.p.PublicRead(f.s, limited, 10, "volume-backup-limits", tenant, query, ""); !errors.Is(err, access.ErrDenied) {
			t.Fatal("tenant reader revealed another scope", tenant, err)
		}
	}
}
