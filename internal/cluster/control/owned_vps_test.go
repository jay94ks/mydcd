// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/config"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/vps"
)

func ownedVPSCredential(t *testing.T, f *nodeStorageFixture, account string, ssh bool) *vps.SealedCredential {
	t.Helper()
	key, _ := vps.DeriveKey(bytes.Repeat([]byte{9}, 32), account)
	c := vps.Credential{AccessKey: "TOKEN-0001"}
	if ssh {
		c.SSHSeed = strings.Repeat("cd", 32)
	}
	s, err := vps.Seal(f.p.Cluster, account, fmt.Sprintf("user-%d", f.next+1), c, key, f.node)
	if err != nil {
		t.Fatal(err)
	}
	return &s
}

func TestOwnedVPSAccountsStayApart(t *testing.T) {
	f := newNodeStorageFixture(t)
	f.apply("admin", "put-vps-account", 0, VPSAccountPut{Name: "home", Vendor: "hostinger", OverageKRWPerGB: 10, Credential: ownedVPSCredential(t, f, "home", true)}, state.Invalid)
	f.apply("admin", "put-vps-account", 0, VPSAccountPut{Name: "home", Vendor: "hostinger", Credential: ownedVPSCredential(t, f, "home", true)}, state.Applied)
	f.apply("admin", "put-vps-account", 1, VPSAccountPut{Name: "main", Vendor: "iwinv", Credential: controlVPSCredential(t, f, "main", f.node)}, state.Applied)

	managed, err := f.p.VPSPage(f.s, f.sessions["admin"], 3, VPSQuery{})
	if err != nil || len(managed.Accounts) != 1 || managed.Accounts[0].Name != "main" {
		t.Fatal("managed page shows owned accounts", managed.Accounts, err)
	}
	owned, err := f.p.OwnedVPSPage(f.s, f.sessions["admin"], 3, OwnedVPSQuery{})
	if err != nil || len(owned.Accounts) != 1 || owned.Accounts[0].Name != "home" || owned.AccountRevision != 2 {
		t.Fatal("owned page", owned, err)
	}
	if _, err := f.p.OwnedVPSPage(f.s, f.sessions["manager"], 3, OwnedVPSQuery{}); err == nil {
		t.Fatal("manager read owned VPS")
	}
	// An owned account never buys a server.
	create := VPSServerCreate{Name: "edge-1", Account: "home", Zone: "Z", Image: "I", Flavor: "F", Script: "S", CapKRW: 1, Port: 8010}
	f.apply("admin", "create-vps-node", 2, create, state.ConditionFailed)
	// A managed account is never attached.
	f.apply("admin", AttachOwnedVPSAction, 0, OwnedVPSAttach{Name: "edge-1", Account: "main", InstanceID: "101", Install: OwnedInstallManual, Port: 8010}, state.ConditionFailed)
}

func TestOwnedVPSAttachDetach(t *testing.T) {
	f := newNodeStorageFixture(t)
	attach := OwnedVPSAttach{Name: "edge-1", Account: "home", InstanceID: "101", Install: OwnedInstallSSH, Port: 8010}
	f.apply("admin", AttachOwnedVPSAction, 0, attach, state.ConditionFailed) // no account
	f.apply("admin", "put-vps-account", 0, VPSAccountPut{Name: "home", Vendor: "hostinger", Credential: ownedVPSCredential(t, f, "home", false)}, state.Applied)
	f.apply("admin", AttachOwnedVPSAction, 0, attach, state.ConditionFailed) // SSH install, account has no SSH key
	f.apply("admin", "put-vps-account", 1, VPSAccountPut{Name: "home", Vendor: "hostinger", Credential: ownedVPSCredential(t, f, "home", true)}, state.Applied)

	f.apply("manager", AttachOwnedVPSAction, 0, attach, state.Forbidden)
	voter := attach
	voter.Voter = true
	f.apply("admin", AttachOwnedVPSAction, 0, voter, state.Invalid) // SSH servers never vote
	bad := attach
	bad.InstanceID = "vm-1"
	f.apply("admin", AttachOwnedVPSAction, 0, bad, state.Invalid)
	bad = attach
	bad.Install = "magic"
	f.apply("admin", AttachOwnedVPSAction, 0, bad, state.Invalid)
	taken := attach
	taken.Name = "node-a" // a member: only --existing may bind it
	f.apply("admin", AttachOwnedVPSAction, 0, taken, state.ConditionFailed)
	f.apply("admin", AttachOwnedVPSAction, 0, attach, state.Applied)
	f.apply("admin", AttachOwnedVPSAction, 0, attach, state.ConditionFailed) // stale revision

	again := attach
	again.Name = "edge-2" // the same instance twice
	f.apply("admin", AttachOwnedVPSAction, 1, again, state.ConditionFailed)
	manual := OwnedVPSAttach{Name: "edge-2", Account: "home", InstanceID: "102", Install: OwnedInstallManual, Voter: true, Protect: OwnedProtectLowWeight, Port: 8010}
	f.apply("admin", AttachOwnedVPSAction, 1, manual, state.Applied)
	existing := OwnedVPSAttach{Name: "edge-3", Account: "home", InstanceID: "103", Install: OwnedInstallExisting}
	f.apply("admin", AttachOwnedVPSAction, 2, existing, state.ConditionFailed) // not a member
	existing.Name = "node-a"
	existing.Port = 8010
	f.apply("admin", AttachOwnedVPSAction, 2, existing, state.Invalid) // existing has its own endpoint
	existing.Port = 0
	f.apply("admin", AttachOwnedVPSAction, 2, existing, state.Applied)

	c, err := f.p.OwnedVPS(f.s)
	if err != nil || c.Revision != 3 || len(c.Servers) != 3 {
		t.Fatal("owned catalog", c, err)
	}
	if v, _ := c.Server("edge-1"); v.Phase != OwnedInstalling || v.Protect != OwnedProtectExclude || v.AttachedBy != "admin" {
		t.Fatalf("edge-1 = %+v", v)
	}
	if v, _ := c.Server("node-a"); v.Phase != OwnedInstalling {
		t.Fatalf("node-a = %+v", v)
	}

	// A managed server cannot take an owned server's name.
	f.apply("admin", "put-vps-account", 2, VPSAccountPut{Name: "main", Vendor: "iwinv", Credential: controlVPSCredential(t, f, "main", f.node)}, state.Applied)
	f.apply("admin", "create-vps-node", 3, VPSServerCreate{Name: "edge-2", Account: "main", Zone: "Z", Image: "I", Flavor: "F", Script: "S", CapKRW: 1, Port: 8010}, state.ConditionFailed)

	f.apply("admin", SetOwnedVPSAction, 3, OwnedVPSSet{Name: "edge-1", Protect: "off"}, state.Invalid)
	f.apply("admin", SetOwnedVPSAction, 3, OwnedVPSSet{Name: "edge-9", Protect: OwnedProtectLowWeight}, state.ConditionFailed)
	f.apply("admin", SetOwnedVPSAction, 3, OwnedVPSSet{Name: "edge-1", Protect: OwnedProtectLowWeight}, state.Applied)

	// The account stays while a server uses it; detach (manual delete) is
	// always possible.
	f.apply("admin", "remove-vps-account", 3, VPSAccountSelection{Name: "home"}, state.ConditionFailed)
	f.apply("admin", DetachOwnedVPSAction, 4, OwnedVPSSelection{Name: "edge-9"}, state.ConditionFailed)
	for i, name := range []string{"edge-1", "edge-2", "node-a"} {
		f.apply("admin", DetachOwnedVPSAction, uint64(4+i), OwnedVPSSelection{Name: name}, state.Applied)
	}
	f.apply("admin", "remove-vps-account", 3, VPSAccountSelection{Name: "home"}, state.Applied)
	if c, _ := f.p.OwnedVPS(f.s); len(c.Servers) != 0 || c.Revision != 7 {
		t.Fatal("not detached", c)
	}
}

func (f *nodeStorageFixture) ownedReport(r OwnedVPSReport, private ed25519.PrivateKey, want state.Code) {
	f.t.Helper()
	r.Schema, r.Cluster, r.Reporter, r.Epoch, r.RootRevision, r.At = 1, f.p.Cluster, [32]byte(private.Public().(ed25519.PublicKey)), f.s.ModuleEpoch(), f.s.Object(OwnedVPSKey).Revision, max(r.At, 10)
	r.Signature = ed25519.Sign(private, OwnedVPSReportBytes(r))
	cmd, err := r.Command()
	if err != nil {
		f.t.Fatal(err)
	}
	n, result, err := state.ApplyAdmitted(f.s, f.s.Index()+1, cmd, f.p.Validate, f.p.Reduce, f.p.AdmitModule)
	if err != nil || result.Code != want {
		f.t.Fatal("owned-vps report", r.Action, result.Code, want, err)
	}
	f.s = n
}

func TestOwnedVPSInstallReports(t *testing.T) {
	f := newNodeStorageFixture(t)
	f.apply("admin", "put-vps-account", 0, VPSAccountPut{Name: "home", Vendor: "hostinger", Credential: ownedVPSCredential(t, f, "home", true)}, state.Applied)
	f.apply("admin", AttachOwnedVPSAction, 0, OwnedVPSAttach{Name: "edge-1", Account: "home", InstanceID: "101", Install: OwnedInstallManual, Port: 8010}, state.Applied)
	f.apply("admin", AttachOwnedVPSAction, 1, OwnedVPSAttach{Name: "node-a", Account: "home", InstanceID: "102", Install: OwnedInstallExisting}, state.Applied)

	// Only a voter reports, and only a well-formed result.
	f.ownedReport(OwnedVPSReport{Server: "edge-1", Action: OwnedChecked, PublicIP: "203.0.113.9", Build: testVPSBuild}, f.admin, state.Forbidden)
	f.ownedReport(OwnedVPSReport{Server: "edge-1", Action: OwnedChecked, PublicIP: "10.0.0.1", Build: testVPSBuild}, f.node, state.Forbidden)
	f.ownedReport(OwnedVPSReport{Server: "edge-1", Action: OwnedChecked, PublicIP: "203.0.113.9"}, f.node, state.ConditionFailed) // a new server needs a build
	// No enrollment before the leader read the address.
	_, newKey, _ := ed25519.GenerateKey(nil)
	peer := config.Peer{ID: "edge-1", Key: hex.EncodeToString(newKey.Public().(ed25519.PublicKey)), Endpoint: "203.0.113.9:8010"}
	f.memberEnroll(peer, "203.0.113.9", f.node, state.Forbidden)
	f.ownedReport(OwnedVPSReport{Server: "edge-1", Action: OwnedChecked, PublicIP: "203.0.113.9", Build: testVPSBuild}, f.node, state.Applied)
	f.ownedReport(OwnedVPSReport{Server: "edge-1", Action: OwnedChecked, PublicIP: "203.0.113.9", Build: testVPSBuild}, f.node, state.ConditionFailed) // once

	// An existing server binds only when its member endpoint is the
	// instance's address (the fixture's node-a is not).
	f.ownedReport(OwnedVPSReport{Server: "node-a", Action: OwnedChecked, PublicIP: "203.0.113.10", Build: testVPSBuild}, f.node, state.ConditionFailed)
	f.ownedReport(OwnedVPSReport{Server: "node-a", Action: OwnedChecked, PublicIP: "203.0.113.10"}, f.node, state.ConditionFailed)
	f.ownedReport(OwnedVPSReport{Server: "node-a", Action: OwnedFailedReport, Failure: "IP_MISMATCH"}, f.node, state.Applied)
	c, _ := f.p.OwnedVPS(f.s)
	if v, _ := c.Server("node-a"); v.Phase != OwnedFailed || v.Failure != "IP_MISMATCH" {
		t.Fatalf("node-a = %+v", v)
	}

	// Enrollment from the instance's address invites the key.
	f.memberEnroll(peer, "198.51.100.7", f.node, state.Forbidden)
	f.memberEnroll(peer, "203.0.113.9", f.node, state.Applied)
	d, _ := f.p.Members(f.s)
	entry, ok := d.Entry("edge-1")
	if v, _ := c.Server("edge-1"); !ok || entry.Phase != membership.Invited || entry.Peer.Voter || entry.JoinID != v.JoinID() {
		t.Fatalf("entry = %+v", entry)
	}
	genesis, _ := d.Entry("node-a")
	inv := membership.Invitation{Schema: 1, Cluster: f.p.Cluster, Admin: f.p.BootstrapKey, Genesis: d.Genesis, Source: genesis.Peer, Target: entry.Peer, JoinID: entry.JoinID, ApprovalRevision: entry.Job.Desired.Revision, MinimumIndex: f.s.Index()}
	inv.Signature = ed25519.Sign(f.node, membership.InvitationBytes(inv))
	f.ownedReport(OwnedVPSReport{Server: "edge-1", Action: OwnedJoined}, f.node, state.ConditionFailed) // not invited yet
	f.ownedReport(OwnedVPSReport{Server: "edge-1", Action: OwnedInvited, Invitation: &inv}, f.node, state.Applied)
	f.ownedReport(OwnedVPSReport{Server: "edge-1", Action: OwnedInvited, Invitation: &inv}, f.node, state.ConditionFailed)
	f.ownedReport(OwnedVPSReport{Server: "edge-1", Action: OwnedJoined}, f.node, state.ConditionFailed) // invited is not joined

	// Join: the same membership steps as a managed VPS.
	akey := [32]byte(f.node.Public().(ed25519.PublicKey))
	ekey := [32]byte(newKey.Public().(ed25519.PublicKey))
	d, _ = f.p.Members(f.s)
	base := uint64(1)
	for _, e := range d.Entries {
		base = max(base, e.NativeIndex+1)
	}
	must := func(n membership.Directory, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		d = n
	}
	e, _ := d.Entry("edge-1")
	must(d.Dispatch("edge-1", e.Revision, e.Job.Pending.ID, base, akey))
	e, _ = d.Entry("edge-1")
	must(d.Observe("edge-1", e.Revision, e.Job.Pending.ID, base+1, peer))
	e, _ = d.Entry("edge-1")
	ack := membership.Ack{Schema: 1, Cluster: f.p.Cluster, Node: "edge-1", JoinID: e.JoinID, Key: ekey, ConfigurationIndex: base + 1, AppliedIndex: base + 1}
	ack.Signature = ed25519.Sign(newKey, membership.AckBytes(ack))
	must(d.Installed(ack, e.Revision))
	must(d.InstallConfiguration(lifecycle.Configuration{Index: base + 1, Members: []lifecycle.Member{{ID: "edge-1", Key: ekey}, {ID: genesis.Peer.ID, Key: akey, Voter: true}}}))
	f.injectMembers(t, d)
	f.ownedReport(OwnedVPSReport{Server: "edge-1", Action: OwnedJoined, At: 11}, f.node, state.Applied)
	c, _ = f.p.OwnedVPS(f.s)
	if v, _ := c.Server("edge-1"); v.Phase != OwnedRunning || v.PublicIP != "203.0.113.9" || v.Invitation == nil {
		t.Fatalf("edge-1 = %+v", v)
	}
	f.ownedReport(OwnedVPSReport{Server: "edge-1", Action: OwnedFailedReport, Failure: "TIMEOUT", At: 12}, f.node, state.ConditionFailed) // only while installing

	// Traffic hold: committed before anything moves, one at a time, in the
	// server's own mode; the leader ends it only after the month.
	const day = 86400
	hold := func(at int64, mode string) *OwnedLimit {
		return &OwnedLimit{At: at, Month: OwnedMonthOf(time.Unix(at, 0)), Mode: mode, UsedMB: 950_000, MonthMB: 1_000_000, ReachAt: at + 3*3600}
	}
	f.ownedReport(OwnedVPSReport{Server: "edge-1", Action: OwnedLimiting, Limit: hold(20, OwnedProtectExclude), At: 21}, f.node, state.Forbidden) // At must match
	f.ownedReport(OwnedVPSReport{Server: "edge-1", Action: OwnedLimiting, Limit: hold(20, OwnedProtectLowWeight), At: 20}, f.node, state.ConditionFailed)
	f.ownedReport(OwnedVPSReport{Server: "edge-1", Action: OwnedRestoredReport, At: 20}, f.node, state.ConditionFailed) // nothing held
	f.ownedReport(OwnedVPSReport{Server: "edge-1", Action: OwnedLimiting, Limit: hold(20, OwnedProtectExclude), At: 20}, f.node, state.Applied)
	c, _ = f.p.OwnedVPS(f.s)
	if h := c.TrafficHolds(); len(h) != 1 || h["edge-1"] != OwnedProtectExclude {
		t.Fatalf("holds = %v", h)
	}
	f.ownedReport(OwnedVPSReport{Server: "edge-1", Action: OwnedLimiting, Limit: hold(30, OwnedProtectExclude), At: 30}, f.node, state.ConditionFailed)
	f.ownedReport(OwnedVPSReport{Server: "edge-1", Action: OwnedRestoredReport, At: 5 * day}, f.node, state.ConditionFailed) // same month
	f.ownedReport(OwnedVPSReport{Server: "edge-1", Action: OwnedRestoredReport, At: 40 * day}, f.node, state.Applied)
	c, _ = f.p.OwnedVPS(f.s)
	if v, _ := c.Server("edge-1"); v.Limit != nil || v.Restored == nil || v.Restored.By != "" || v.Restored.Month != "1970-02" {
		t.Fatalf("restored = %+v", v)
	}

	// An operator ends a hold at once, and the leader leaves it that month.
	f.ownedReport(OwnedVPSReport{Server: "edge-1", Action: OwnedLimiting, Limit: hold(41*day, OwnedProtectExclude), At: 41 * day}, f.node, state.Applied)
	c, _ = f.p.OwnedVPS(f.s)
	f.apply("admin", SetOwnedVPSAction, c.Revision, OwnedVPSSet{Name: "edge-1"}, state.Invalid)
	f.apply("admin", SetOwnedVPSAction, c.Revision, OwnedVPSSet{Name: "edge-1", Restore: true}, state.Applied)
	f.ownedReport(OwnedVPSReport{Server: "edge-1", Action: OwnedLimiting, Limit: hold(42*day, OwnedProtectExclude), At: 42 * day}, f.node, state.ConditionFailed)
	c, _ = f.p.OwnedVPS(f.s)
	f.apply("admin", SetOwnedVPSAction, c.Revision, OwnedVPSSet{Name: "edge-1", Restore: true}, state.ConditionFailed)                                    // nothing held
	f.ownedReport(OwnedVPSReport{Server: "edge-1", Action: OwnedLimiting, Limit: hold(70*day, OwnedProtectExclude), At: 70 * day}, f.node, state.Applied) // next month

	// The subscription ended: failed, EXPIRED; removing it is the operator's.
	f.ownedReport(OwnedVPSReport{Server: "edge-1", Action: OwnedExpired, At: 80 * day}, f.node, state.Applied)
	c, _ = f.p.OwnedVPS(f.s)
	if v, _ := c.Server("edge-1"); v.Phase != OwnedFailed || v.Failure != "EXPIRED" || v.Limit != nil {
		t.Fatalf("expired = %+v", v)
	}
	if h := c.TrafficHolds(); len(h) != 0 {
		t.Fatalf("expired holds = %v", h)
	}
}
