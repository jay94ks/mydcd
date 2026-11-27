// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/observability"
)

func TestPublicReadProjectionUsesCurrentTasksAndKeepsUnknownNativeFactsUnknown(t *testing.T) {
	f, _, _ := logClearPlanFixture(t, "local")
	before, _ := state.Encode(f.s)
	page, err := f.p.PublicRead(f.s, f.session, 10, "network-users", "tenant", PublicReadQuery{Name: "services"}, "")
	if err != nil || len(page.Rows) != 1 || page.Rows[0].User == nil {
		t.Fatal("original network consumer", page, err)
	}
	row := page.Rows[0].User
	if row.App != "source-app" || row.Service != "web" || !row.Live || row.EndpointPresent != nil {
		t.Fatal("desired reference/unknown endpoint", row)
	}
	raw, _ := json.Marshal(page)
	for _, private := range []string{"Signature", "VerifierRef", "Password", "Session", "Environment"} {
		if bytes.Contains(raw, []byte(private)) {
			t.Fatal("private data in public page", private)
		}
	}
	after, _ := state.Encode(f.s)
	if !bytes.Equal(before, after) {
		t.Fatal("read changed the original FSM")
	}
	if _, err = f.p.PublicRead(f.s, f.session, 10, "network-users", "foreign", PublicReadQuery{Name: "services"}, ""); !errors.Is(err, access.ErrDenied) {
		t.Fatal("foreign existence read", err)
	}
	trust, err := f.p.PublicRead(f.s, f.session, 10, "image-trust", "tenant", PublicReadQuery{}, "")
	if err != nil || len(trust.Rows) != 1 || trust.Rows[0].Image == nil || trust.TenantRevision == 0 {
		t.Fatal("same retained task image/trust source", trust, err)
	}
	// The issued signature alone is insufficient after an account mutation.
	// Retain the required second active administrator before disabling this one.
	f.apply("public-read-other-admin", "put-user", 0, access.User{ID: "other-admin", Username: "other-admin", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: [32]byte(f.admin.Public().(ed25519.PublicKey)), Enabled: true}}}, state.Applied)
	catalog, _ := f.p.Catalog(f.s)
	user, _ := catalog.User(f.session.User)
	user.Enabled = false
	expected := user.Revision
	user.Revision = 0
	f.apply("public-read-disable", "put-user", expected, accountFields(user), state.Applied)
	if _, err = f.p.PublicRead(f.s, f.session, 10, "network-users", "tenant", PublicReadQuery{Name: "services"}, ""); !errors.Is(err, access.ErrDenied) {
		t.Fatal("old session kept metadata authority", err)
	}
}

func TestPublicBackupLimitUsesExactCASAndSameReservationAccounting(t *testing.T) {
	f := newBackupCore(t)
	f.limits()
	page, err := f.p.PublicRead(f.s, f.session, 10, "volume-backup-limits", "tenant", PublicReadQuery{}, "")
	if err != nil || len(page.Rows) != 1 || page.Rows[0].BackupLimit == nil || page.RootRevision != f.s.Object(VolumesKey).Revision {
		t.Fatal("limit CAS projection", page, err)
	}
	own := page.Rows[0].BackupLimit
	if !own.GlobalPresent || own.Tenant != "tenant" || own.Bytes != 65536 || own.Count != 1 || own.UsedCount != 0 {
		t.Fatal("limit/usage mismatch", own)
	}
	global, err := f.p.PublicRead(f.s, f.session, 10, "volume-backup-limits", "", PublicReadQuery{}, "")
	if err != nil || len(global.Rows) != 1 || global.Rows[0].BackupLimit.Tenant != "" {
		t.Fatal("admin global limit", global, err)
	}
	limited := f.session
	limited.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read}}}
	limited.Signature = ed25519.Sign(f.node, access.SessionBytes(limited))
	if _, err = f.p.PublicRead(f.s, limited, 10, "volume-backup-limits", "", PublicReadQuery{}, ""); !errors.Is(err, access.ErrDenied) {
		t.Fatal("tenant read revealed global values", err)
	}
	bad := page
	bad.Rows[0].BackupLimit.Bytes++
	fresh, err := f.p.PublicRead(f.s, f.session, 10, "volume-backup-limits", "tenant", PublicReadQuery{}, "")
	if err != nil || fresh.Rows[0].BackupLimit.Bytes != 65536 {
		t.Fatal("returned DTO aliased authority", err)
	}
}

func TestPublicBackupLimitMissingRowsAndCurrentCASUpdate(t *testing.T) {
	f := newBackupCore(t)
	query := PublicReadQuery{Node: "node-a"}
	read := func(session access.Session, tenant string) PublicReadPage {
		t.Helper()
		page, err := f.p.PublicRead(f.s, session, 10, "volume-backup-limits", tenant, query, "")
		if err != nil {
			t.Fatal(err)
		}
		return page
	}
	if page := read(f.session, "tenant"); len(page.Rows) != 0 {
		t.Fatal("missing limit fabricated a zero-valued row", page)
	}
	limited := f.session
	limited.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read}}}
	limited.Signature = ed25519.Sign(f.node, access.SessionBytes(limited))
	f.apply("own-only", "set-volume-backup-limit", 0, VolumeBackupLimit{Tenant: "tenant", Node: "node-a", Bytes: 65536, Count: 1}, state.Applied)
	own := read(limited, "tenant").Rows[0].BackupLimit
	if own.GlobalPresent || own.Revision == 0 {
		t.Fatal("missing global limit claimed present", own)
	}
	f.apply("new-own-budget", "set-volume-backup-limit", own.Revision, VolumeBackupLimit{Tenant: "tenant", Node: "node-a", Bytes: 131072, Count: 2, StagingBytes: 65536, StagingCount: 1}, state.Applied)
	current := read(limited, "tenant").Rows[0].BackupLimit
	if current.Revision <= own.Revision || current.Bytes != 131072 || current.Count != 2 || current.StagingBytes != 65536 || current.StagingCount != 1 || current.UsedCount != 0 || current.UsedBytes != 0 || current.UsedStagingCount != 0 || current.UsedStagingBytes != 0 {
		t.Fatal("public budget did not consume current CAS", current)
	}
	f.apply("stale-budget", "set-volume-backup-limit", own.Revision, VolumeBackupLimit{Tenant: "tenant", Node: "node-a", Bytes: 262144, Count: 3}, state.ConditionFailed)
	f.apply("global-budget", "set-volume-backup-limit", 0, VolumeBackupLimit{Node: "node-a", Bytes: 1048576, Count: 8}, state.Applied)
	current = read(limited, "tenant").Rows[0].BackupLimit
	if !current.GlobalPresent || current.Bytes != 131072 {
		t.Fatal("tenant projection included global values", current)
	}
	for _, tenant := range []string{"", "foreign"} {
		if _, err := f.p.PublicRead(f.s, limited, 10, "volume-backup-limits", tenant, query, ""); !errors.Is(err, access.ErrDenied) {
			t.Fatal("read escaped current tenant", tenant, err)
		}
	}
	query.Node = "node-without-limit"
	if page := read(limited, "tenant"); len(page.Rows) != 0 {
		t.Fatal("unknown node limit fabricated a row", page)
	}
}

func TestCordonPublicMetadataUsesOriginalSignedActorTimeAndClearsOnUncordon(t *testing.T) {
	f := newBackupCore(t)
	f.session.Scopes[0].Actions = append(f.session.Scopes[0].Actions, access.ManageMembers)
	f.session.Signature = ed25519.Sign(f.node, access.SessionBytes(f.session))
	members, err := f.p.Members(f.s)
	if err != nil {
		t.Fatal(err)
	}
	configuration := lifecycle.Configuration{Index: 1, Members: []lifecycle.Member{{ID: "node-a", Key: f.p.TrustRoot, Voter: true}}}
	nodeCoreReport(t, f, MemberReport{Action: "configuration", Node: "node-a", Expected: members.Revision, Configuration: &configuration}, state.Applied)
	managedDNSChange(t, f, "public-cordon", "cordon-node", 0, NodeSelection{ID: "node-a"}, state.Applied)
	view, ok := f.p.PublicNodeView(f.s, "node-a")
	if !ok || !view.Scheduling.Enabled || view.Scheduling.CordonedBy != "admin" || view.Scheduling.CordonedAt != time.Unix(2, 0).UTC().Format(time.RFC3339) {
		t.Fatal("original scheduling actor/time", view)
	}
	managedDNSChange(t, f, "public-uncordon", "uncordon-node", 1, NodeSelection{ID: "node-a"}, state.Applied)
	view, ok = f.p.PublicNodeView(f.s, "node-a")
	if !ok || view.Scheduling.Enabled || view.Scheduling.CordonedBy != "" || view.Scheduling.CordonedAt != "" {
		t.Fatal("uncordon retained old actor/time", view)
	}
	// cordon-node's NodeCordonChange.Reason is projected from the original.
	managedDNSChange(t, f, "public-cordon-bad", "cordon-node", 2, NodeCordonChange{ID: "node-a", Reason: "two\nlines"}, state.Invalid)
	managedDNSChange(t, f, "public-cordon-why", "cordon-node", 2, NodeCordonChange{ID: "node-a", Reason: "디스크 경보"}, state.Applied)
	view, ok = f.p.PublicNodeView(f.s, "node-a")
	if !ok || !view.Scheduling.Enabled || view.Scheduling.Reason != "디스크 경보" || view.Scheduling.CordonedBy != "admin" {
		t.Fatal("cordon reason", view)
	}
	managedDNSChange(t, f, "public-uncordon-why", "uncordon-node", 3, NodeSelection{ID: "node-a"}, state.Applied)
	if view, ok = f.p.PublicNodeView(f.s, "node-a"); !ok || view.Scheduling.Reason != "" {
		t.Fatal("uncordon retained the reason", view)
	}
	page, err := f.p.NodeSummary(f.s, f.session, 10, "tenant", "node-a", "", nil, true)
	if err != nil || len(page.Nodes) != 1 || page.Nodes[0].ObserveLimitSeconds != observability.MaxAge/1000 || page.Nodes[0].State != "unreachable" {
		t.Fatal("same freshness limit/status", page, err)
	}
}

func TestNetworkUsersConsumesOnlyFreshEndpointEvidenceAndOwnsPointer(t *testing.T) {
	f, o, _ := logClearPlanFixture(t, "local")
	for _, mode := range []string{"present", "absent", "missing", "unknown", "legacy"} {
		o.Sequence++
		o.Healthy = mode != "missing" && mode != "unknown"
		o.TaskFact = &containerops.TaskFact{Name: "owned-endpoint", State: "running"}
		want := (*bool)(nil)
		if mode == "present" || mode == "absent" {
			value := mode == "present"
			o.TaskFact.EndpointPresent, want = &value, &value
		}
		if mode == "unknown" {
			value := true
			o.TaskFact.State, o.TaskFact.EndpointPresent = "unknown", &value
		}
		if mode == "missing" {
			o.TaskFact.State = "missing"
			value := false
			want = &value
		}
		o.Signature = ed25519.Sign(f.node, deployment.ObservationBytes(o))
		managedDNSTaskCoreProgress(t, f, "source-app", "observe", o.Key, &o)
		page, err := f.p.PublicRead(f.s, f.session, 10, "network-users", "tenant", PublicReadQuery{Name: "services"}, "")
		if err != nil || len(page.Rows) != 1 || page.Rows[0].User == nil {
			t.Fatal("network consumer reference lost", mode, err)
		}
		row := page.Rows[0].User
		if !row.Live || (row.EndpointPresent == nil) != (want == nil) || want != nil && *row.EndpointPresent != *want {
			t.Fatal("network-users guessed endpoint from reference/process", mode, row)
		}
		if row.EndpointPresent != nil {
			*row.EndpointPresent = !*row.EndpointPresent
			again, err := f.p.PublicRead(f.s, f.session, 10, "network-users", "tenant", PublicReadQuery{Name: "services"}, "")
			if err != nil || again.Rows[0].User.EndpointPresent == nil || *again.Rows[0].User.EndpointPresent != *want {
				t.Fatal("public endpoint pointer aliases original source", err)
			}
		}
		stale, err := f.p.PublicRead(expireAll(t, f.p, f.s, f.node, o.At+AppObservationMaxAge+1), f.session, int64(o.At+AppObservationMaxAge+1), "network-users", "tenant", PublicReadQuery{Name: "services"}, "")
		if err != nil || stale.Rows[0].User.EndpointPresent != nil || !stale.Rows[0].User.Live {
			t.Fatal("stale endpoint conflated absence/unknown or hid desired reference", err)
		}
	}
	value := true
	task := TaskView{Observed: "running", EndpointPresent: &value}
	public := publicTaskUser(task)
	*public.EndpointPresent = false
	if !*task.EndpointPresent {
		t.Fatal("publicTaskUser did not own its endpoint pointer")
	}
	task.Observed = "unknown"
	if publicTaskUser(task).EndpointPresent != nil {
		t.Fatal("unknown Task retained an endpoint pointer as actual proof")
	}
}
