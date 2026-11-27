// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
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

func controlVPSCredential(t *testing.T, f *nodeStorageFixture, account string, sealer ed25519.PrivateKey) *vps.SealedCredential {
	t.Helper()
	key, _ := vps.DeriveKey(bytes.Repeat([]byte{9}, 32), account)
	s, err := vps.Seal(f.p.Cluster, account, fmt.Sprintf("user-%d", f.next+1), vps.Credential{AccessKey: "AK-0001", SecretKey: "SECRET"}, key, sealer)
	if err != nil {
		t.Fatal(err)
	}
	return &s
}

func TestVPSAccountsAreSystemAdminOnlyAndSealedByAVoter(t *testing.T) {
	f := newNodeStorageFixture(t)
	f.apply("manager", "put-vps-account", 0, VPSAccountPut{Name: "main", Vendor: "iwinv", Credential: controlVPSCredential(t, f, "main", f.node)}, state.Forbidden)
	// A sealer that is not a voter is refused.
	f.apply("admin", "put-vps-account", 0, VPSAccountPut{Name: "main", Vendor: "iwinv", Credential: controlVPSCredential(t, f, "main", f.manager)}, state.Forbidden)
	// A credential sealed for another write or account is refused.
	other := controlVPSCredential(t, f, "other", f.node)
	f.apply("admin", "put-vps-account", 0, VPSAccountPut{Name: "main", Vendor: "iwinv", Credential: other}, state.Invalid)
	f.apply("admin", "put-vps-account", 0, VPSAccountPut{Name: "main", Vendor: "nope", Credential: controlVPSCredential(t, f, "main", f.node)}, state.Invalid)
	f.apply("admin", "put-vps-account", 0, VPSAccountPut{Name: "main", Vendor: "iwinv"}, state.ConditionFailed)
	f.apply("admin", "put-vps-account", 0, VPSAccountPut{Name: "main", Vendor: "iwinv", OverageKRWPerGB: 50, Credential: controlVPSCredential(t, f, "main", f.node)}, state.Applied)
	f.apply("admin", "put-vps-account", 0, VPSAccountPut{Name: "main", Vendor: "iwinv", OverageKRWPerGB: 60}, state.ConditionFailed)
	f.apply("admin", "put-vps-account", 1, VPSAccountPut{Name: "main", Vendor: "iwinv", OverageKRWPerGB: 60}, state.Applied)

	page, err := f.p.VPSPage(f.s, f.sessions["admin"], 3, VPSQuery{})
	if err != nil || page.Revision != 2 || len(page.Accounts) != 1 || page.Accounts[0].OverageKRWPerGB != 60 || page.Accounts[0].KeyHint != "0001" || page.Accounts[0].AddedBy != "admin" {
		t.Fatal("account page", page, err)
	}
	public, _ := json.Marshal(page)
	if bytes.Contains(public, []byte("Box")) || bytes.Contains(public, []byte("SECRET")) {
		t.Fatal("sealed credential in the public page")
	}
	if _, err := f.p.VPSPage(f.s, f.sessions["manager"], 3, VPSQuery{}); err == nil {
		t.Fatal("manager read accounts")
	}
	c, _ := f.p.VPS(f.s)
	a, _ := c.Account("main")
	key, _ := vps.DeriveKey(bytes.Repeat([]byte{9}, 32), "main")
	if cred, err := vps.Open(a.Credential, key); err != nil || cred.SecretKey != "SECRET" {
		t.Fatal("stored credential does not open", err)
	}
	f.apply("admin", "remove-vps-account", 2, VPSAccountSelection{Name: "nope"}, state.ConditionFailed)
	f.apply("admin", "remove-vps-account", 2, VPSAccountSelection{Name: "main"}, state.Applied)
	if c, err := f.p.VPS(f.s); err != nil || len(c.Accounts) != 0 || c.Revision != 3 {
		t.Fatal("account not removed", err)
	}
}

func (f *nodeStorageFixture) vpsReport(r VPSReport, private ed25519.PrivateKey, want state.Code) {
	f.t.Helper()
	r.Schema, r.Cluster, r.Reporter, r.Epoch, r.RootRevision, r.At = 1, f.p.Cluster, [32]byte(private.Public().(ed25519.PublicKey)), f.s.ModuleEpoch(), f.s.Object(VPSKey).Revision, max(r.At, 10)
	r.Signature = ed25519.Sign(private, VPSReportBytes(r))
	cmd, err := r.Command()
	if err != nil {
		f.t.Fatal(err)
	}
	n, result, err := state.ApplyAdmitted(f.s, f.s.Index()+1, cmd, f.p.Validate, f.p.Reduce, f.p.AdmitModule)
	if err != nil || result.Code != want {
		f.t.Fatal("vps report", r.Action, result.Code, want, err)
	}
	f.s = n
}

func TestVPSAccountSSHKey(t *testing.T) {
	f := newNodeStorageFixture(t)
	f.apply("admin", "put-vps-account", 0, VPSAccountPut{Name: "main", Vendor: "iwinv", Credential: controlVPSCredential(t, f, "main", f.node)}, state.Applied)
	// The test credential has no SSH key: nothing to register.
	f.apply("admin", "put-vps-account", 1, VPSAccountPut{Name: "main", Vendor: "iwinv", SSHKeyID: "K9"}, state.Invalid)
	key, _ := vps.DeriveKey(bytes.Repeat([]byte{9}, 32), "main")
	sealed, err := vps.Seal(f.p.Cluster, "main", fmt.Sprintf("user-%d", f.next+1), vps.Credential{AccessKey: "AK-0002", SecretKey: "S", SSHSeed: strings.Repeat("cd", 32)}, key, f.node)
	if err != nil {
		t.Fatal(err)
	}
	f.apply("admin", "put-vps-account", 1, VPSAccountPut{Name: "main", Vendor: "iwinv", Credential: &sealed}, state.Applied)
	f.apply("admin", "put-vps-account", 2, VPSAccountPut{Name: "main", Vendor: "iwinv", SSHKeyID: "K9"}, state.Applied)
	page, _ := f.p.VPSPage(f.s, f.sessions["admin"], 3, VPSQuery{})
	if a := page.Accounts[0]; a.SSHKeyID != "K9" || !strings.HasPrefix(a.SSHPublic, "ssh-ed25519 ") {
		t.Fatalf("account = %+v", a)
	}
	create := VPSServerCreate{Name: "edge-1", Account: "main", Zone: "Z", Image: "I", Flavor: "F", SSHKeys: []string{"K1"}, CapKRW: 1, Port: 8010}
	f.apply("admin", "create-vps-node", 3, create, state.ConditionFailed)
	create.SSHKeys = []string{"K1", "K9"}
	voter := create
	voter.Voter = true
	f.apply("admin", "create-vps-node", 3, voter, state.Invalid) // SSH servers never vote
	f.apply("admin", "create-vps-node", 3, create, state.Applied)
	// A new key pair brings a new SSH key and forgets the registration.
	again := controlVPSCredential(t, f, "main", f.node)
	f.apply("admin", "put-vps-account", 4, VPSAccountPut{Name: "main", Vendor: "iwinv", Credential: again, SSHKeyID: "K9"}, state.Invalid)
	f.apply("admin", "put-vps-account", 4, VPSAccountPut{Name: "main", Vendor: "iwinv", Credential: controlVPSCredential(t, f, "main", f.node)}, state.Applied)
	if c, _ := f.p.VPS(f.s); c.Accounts[0].SSHKeyID != "" {
		t.Fatal("rotation kept the old ssh key id")
	}
}

func TestVPSServerCreateAndLeaderReport(t *testing.T) {
	f := newNodeStorageFixture(t)
	create := VPSServerCreate{Name: "edge-1", Account: "main", Zone: "KR1-Z01", Image: "PIMAGE-u", Flavor: "F1", Script: "S1", SSHKeys: []string{"K1", "K2"}, CapKRW: 30000, Port: 8010}
	f.apply("admin", "create-vps-node", 0, create, state.ConditionFailed) // no account yet
	f.apply("admin", "put-vps-account", 0, VPSAccountPut{Name: "main", Vendor: "iwinv", Credential: controlVPSCredential(t, f, "main", f.node)}, state.Applied)
	f.apply("manager", "create-vps-node", 1, create, state.Forbidden)
	bad := create
	bad.SSHKeys = []string{"K2", "K1"}
	f.apply("admin", "create-vps-node", 1, bad, state.Invalid)
	// Without a script the account's registered SSH key must be on it.
	viaSSH := create
	viaSSH.Script = ""
	f.apply("admin", "create-vps-node", 1, viaSSH, state.ConditionFailed)
	taken := create
	taken.Name = "node-a"
	f.apply("admin", "create-vps-node", 1, taken, state.ConditionFailed)
	f.apply("admin", "create-vps-node", 1, create, state.Applied)
	f.apply("admin", "create-vps-node", 2, create, state.ConditionFailed)
	f.apply("admin", "remove-vps-account", 2, VPSAccountSelection{Name: "main"}, state.ConditionFailed)

	c, _ := f.p.VPS(f.s)
	v, ok := c.Server("edge-1")
	if !ok || v.Phase != VPSCreating || v.Request == "" || v.Tag(f.p.Cluster) != "sfc:68000000:"+v.Request || v.Voter {
		t.Fatalf("server = %+v", v)
	}
	// Only a voter reports, and only a well-formed result.
	f.vpsReport(VPSReport{Server: "edge-1", Action: VPSInstalling, InstanceID: "INSTANCE-1", PublicIP: "203.0.113.9"}, f.admin, state.Forbidden)
	f.vpsReport(VPSReport{Server: "edge-1", Action: VPSInstalling, InstanceID: "INSTANCE-1", PublicIP: "10.0.0.1"}, f.node, state.Forbidden)
	f.vpsReport(VPSReport{Server: "edge-1", Action: VPSCreateSent, Failure: "X"}, f.node, state.Forbidden)
	f.vpsReport(VPSReport{Server: "edge-1", Action: VPSCreateSent}, f.node, state.Applied)
	f.vpsReport(VPSReport{Server: "edge-1", Action: VPSCreateSent}, f.node, state.ConditionFailed) // only once
	if c, _ := f.p.VPS(f.s); c.Servers[0].CreateSentAt == 0 || c.Servers[0].Phase != VPSCreating {
		t.Fatalf("create-sent = %+v", c.Servers[0])
	}
	f.vpsReport(VPSReport{Server: "nope", Action: VPSInstalling, InstanceID: "INSTANCE-1", PublicIP: "203.0.113.9", Build: testVPSBuild}, f.node, state.ConditionFailed)
	f.vpsReport(VPSReport{Server: "edge-1", Action: VPSInstalling, InstanceID: "INSTANCE-1", PublicIP: "203.0.113.9", Build: testVPSBuild}, f.node, state.Applied)
	f.vpsReport(VPSReport{Server: "edge-1", Action: VPSFailed, Failure: "TIMEOUT"}, f.node, state.ConditionFailed)
	c, _ = f.p.VPS(f.s)
	if v, _ := c.Server("edge-1"); v.Phase != VPSInstalling || v.InstanceID != "INSTANCE-1" || v.PublicIP != "203.0.113.9" {
		t.Fatalf("after report = %+v", v)
	}
	page, err := f.p.VPSPage(f.s, f.sessions["admin"], 3, VPSQuery{})
	if err != nil || len(page.Servers) != 1 {
		t.Fatal("page servers", page, err)
	}

	// Enrollment: an ingress member attests the source address; the
	// signed create-vps-node is the authority to invite.
	_, newKey, _ := ed25519.GenerateKey(nil)
	pub := newKey.Public().(ed25519.PublicKey)
	peer := config.Peer{ID: "edge-1", Key: hex.EncodeToString(pub), Endpoint: "203.0.113.9:8010"}
	f.memberEnroll(peer, "198.51.100.7", f.node, state.Forbidden) // not from the VPS
	wrong := peer
	wrong.Endpoint = "203.0.113.9:9999"
	f.memberEnroll(wrong, "203.0.113.9", f.node, state.Forbidden)
	f.memberEnroll(peer, "203.0.113.9", f.manager, state.Forbidden) // not a member
	f.memberEnroll(peer, "203.0.113.9", f.node, state.Applied)
	d, _ := f.p.Members(f.s)
	entry, ok := d.Entry("edge-1")
	if !ok || entry.Phase != membership.Invited || entry.Peer.Voter || entry.JoinID != v.JoinID() {
		t.Fatalf("entry = %+v", entry)
	}
	genesis, _ := d.Entry("node-a")
	inv := membership.Invitation{Schema: 1, Cluster: f.p.Cluster, Admin: f.p.BootstrapKey, Genesis: d.Genesis, Source: genesis.Peer, Target: entry.Peer, JoinID: entry.JoinID, ApprovalRevision: entry.Job.Desired.Revision, MinimumIndex: f.s.Index()}
	inv.Signature = ed25519.Sign(f.node, membership.InvitationBytes(inv))
	forged := inv
	forged.Signature = ed25519.Sign(f.admin, membership.InvitationBytes(inv))
	f.vpsReport(VPSReport{Server: "edge-1", Action: VPSInvited, Invitation: &forged}, f.node, state.Forbidden)
	f.vpsReport(VPSReport{Server: "edge-1", Action: VPSInvited, Invitation: &inv}, f.node, state.Applied)
	f.vpsReport(VPSReport{Server: "edge-1", Action: VPSInvited, Invitation: &inv}, f.node, state.ConditionFailed)
	c, _ = f.p.VPS(f.s)
	if v, _ := c.Server("edge-1"); v.Invitation == nil || v.Invitation.Target.Key != peer.Key {
		t.Fatalf("invitation not stored: %+v", v)
	}
	// Running needs the invited key to be a full member; invited is not.
	f.vpsReport(VPSReport{Server: "edge-1", Action: VPSRunning}, f.node, state.ConditionFailed)

	invited := f.s
	defer func() {
		// From the same invited state: once joined, the server must
		// leave the membership before it is deleted.
		f.s = invited
		f.vpsJoinAndRemove(t, peer, newKey)
	}()

	// Delete: a server that never joined (only invited) goes at once.
	f.vpsReport(VPSReport{Server: "edge-1", Action: VPSDeleted}, f.node, state.ConditionFailed) // not deleting
	f.apply("admin", "delete-vps-node", c.Revision, VPSServerSelection{Name: "nope"}, state.ConditionFailed)
	f.apply("manager", "delete-vps-node", c.Revision, VPSServerSelection{Name: "edge-1"}, state.Forbidden)
	f.apply("admin", "delete-vps-node", c.Revision, VPSServerSelection{Name: "edge-1"}, state.Applied)
	c, _ = f.p.VPS(f.s)
	if v, _ := c.Server("edge-1"); v.Phase != VPSDeleting || v.DeleteRequest == "" || v.InstanceID != "INSTANCE-1" {
		t.Fatalf("deleting = %+v", v)
	}
	f.apply("admin", "delete-vps-node", c.Revision, VPSServerSelection{Name: "edge-1"}, state.ConditionFailed) // already deleting
	// The stored invitation no longer joins a server being deleted.
	f.memberDispatch("edge-1", state.ConditionFailed)
	f.vpsReport(VPSReport{Server: "edge-1", Action: VPSDeleted, InstanceID: "INSTANCE-1"}, f.node, state.Forbidden)
	f.vpsReport(VPSReport{Server: "edge-1", Action: VPSDeleted}, f.admin, state.Forbidden) // not a voter
	f.vpsReport(VPSReport{Server: "edge-1", Action: VPSDeleted}, f.node, state.Applied)
	c, _ = f.p.VPS(f.s)
	if _, ok := c.Server("edge-1"); ok {
		t.Fatal("record not removed")
	}
	f.apply("admin", "remove-vps-account", c.Revision, VPSAccountSelection{Name: "main"}, state.Applied)
}

// vpsJoinAndRemove moves the invited edge-1 to a full member (running),
// checks it cannot be deleted while it is one, removes it from the
// membership and deletes it then.
func (f *nodeStorageFixture) vpsJoinAndRemove(t *testing.T, peer config.Peer, private ed25519.PrivateKey) {
	t.Helper()
	d, err := f.p.Members(f.s)
	if err != nil {
		t.Fatal(err)
	}
	akey := [32]byte(f.node.Public().(ed25519.PublicKey))
	ekey := [32]byte(private.Public().(ed25519.PublicKey))
	steps := 0
	step := func(n membership.Directory, err error) {
		t.Helper()
		steps++
		if err != nil {
			t.Fatal("membership step", steps, err)
		}
		d = n
	}
	base := uint64(1)
	for _, e := range d.Entries {
		base = max(base, e.NativeIndex+1)
	}
	genesis, _ := d.Entry("node-a")
	a := lifecycle.Member{ID: genesis.Peer.ID, Key: akey, Voter: true}
	if d.Runtime != nil {
		t.Fatal("fixture already has a runtime")
	}
	e, _ := d.Entry("edge-1")
	step(d.Dispatch("edge-1", e.Revision, e.Job.Pending.ID, base, akey))
	e, _ = d.Entry("edge-1")
	step(d.Observe("edge-1", e.Revision, e.Job.Pending.ID, base+1, peer))
	e, _ = d.Entry("edge-1")
	ack := membership.Ack{Schema: 1, Cluster: f.p.Cluster, Node: "edge-1", JoinID: e.JoinID, Key: ekey, ConfigurationIndex: base + 1, AppliedIndex: base + 1}
	ack.Signature = ed25519.Sign(private, membership.AckBytes(ack))
	step(d.Installed(ack, e.Revision))
	c := lifecycle.Configuration{Index: base + 1, Members: []lifecycle.Member{{ID: "edge-1", Key: ekey}, a}} // sorted by ID
	step(d.InstallConfiguration(c))
	f.injectMembers(t, d)

	// A later report than the refused one (its receipt would answer again).
	f.vpsReport(VPSReport{Server: "edge-1", Action: VPSRunning, At: 11}, f.node, state.Applied)
	cat, _ := f.p.VPS(f.s)
	if v, _ := cat.Server("edge-1"); v.Phase != VPSRunning {
		t.Fatalf("running = %+v", v)
	}
	f.apply("admin", "delete-vps-node", cat.Revision, VPSServerSelection{Name: "edge-1"}, state.ConditionFailed) // still a member

	// Stop needs a cordoned, drained member; then the DNS wait, then off.
	stop := VPSServerStop{Name: "edge-1", DNSWaitSeconds: 300}
	f.apply("admin", "stop-vps-node", cat.Revision, VPSServerStop{Name: "edge-1", DNSWaitSeconds: MaxVPSDNSWait + 1}, state.Invalid)
	f.apply("admin", "stop-vps-node", cat.Revision, stop, state.ConditionFailed) // not cordoned
	f.apply("admin", "cordon-node", 0, NodeSelection{ID: "edge-1"}, state.Applied)
	f.apply("admin", "stop-vps-node", cat.Revision, stop, state.ConditionFailed) // not drained
	drain, err := f.p.PlanNodeDrain(f.s, f.sessions["admin"], 2, NodeDrainQuery{Node: "edge-1", Operation: "drain-edge"})
	if err != nil {
		t.Fatal(err)
	}
	f.apply("admin", "drain-node", drain.Expected, NodeDrainChange{At: drain.At, ID: drain.Node, Operation: drain.Operation, AppsRoot: drain.AppsRoot, Plan: drain.Digest, Jobs: drain.Jobs}, state.Applied)
	f.apply("admin", "start-vps-node", cat.Revision, VPSServerSelection{Name: "edge-1"}, state.ConditionFailed) // not stopped
	f.apply("admin", "stop-vps-node", cat.Revision, stop, state.Applied)
	cat, _ = f.p.VPS(f.s)
	v, _ := cat.Server("edge-1")
	if v.Phase != VPSStopping || v.PowerRequest == "" || v.StopAfter != v.PhaseAt+300 {
		t.Fatalf("stopping = %+v", v)
	}
	f.vpsReport(VPSReport{Server: "edge-1", Action: VPSStopped, At: uint64(v.StopAfter - 1)}, f.node, state.ConditionFailed) // DNS wait not over
	f.vpsReport(VPSReport{Server: "edge-1", Action: VPSStarted, At: uint64(v.StopAfter)}, f.node, state.ConditionFailed)     // not starting
	f.vpsReport(VPSReport{Server: "edge-1", Action: VPSStopped, At: uint64(v.StopAfter)}, f.node, state.Applied)
	cat, _ = f.p.VPS(f.s)
	f.apply("admin", "start-vps-node", cat.Revision, VPSServerSelection{Name: "edge-1"}, state.Applied)
	f.vpsReport(VPSReport{Server: "edge-1", Action: VPSStarted, At: uint64(v.StopAfter + 1)}, f.node, state.Applied)
	cat, _ = f.p.VPS(f.s)
	if v, _ := cat.Server("edge-1"); v.Phase != VPSRunning {
		t.Fatalf("started = %+v", v)
	}

	// The monthly cap: the leader stops the server, with no drain, after
	// the DNS wait; it starts again only with a cap above the projection.
	v, _ = cat.Server("edge-1")
	at := v.PhaseAt + 10
	over := &VPSCapStop{At: at, Month: vps.MonthOf(time.Unix(at, 0)), CapKRW: v.CapKRW, SoFarKRW: 1000, ProjectedKRW: v.CapKRW + 5000}
	under := *over
	under.ProjectedKRW = v.CapKRW
	f.vpsReport(VPSReport{Server: "edge-1", Action: VPSCapped, At: uint64(at), Cap: &under}, f.node, state.Forbidden) // not over the cap
	stale := *over
	stale.CapKRW = v.CapKRW + 1
	stale.ProjectedKRW = v.CapKRW + 6000
	f.vpsReport(VPSReport{Server: "edge-1", Action: VPSCapped, At: uint64(at), Cap: &stale}, f.node, state.ConditionFailed) // judged against another cap
	// An operator who picked notify keeps the server running.
	f.apply("admin", "set-vps-node-cap", cat.Revision, VPSServerCap{Name: "edge-1", CapKRW: v.CapKRW, CapAction: "drain"}, state.Invalid)
	f.apply("admin", "set-vps-node-cap", cat.Revision, VPSServerCap{Name: "edge-1", CapKRW: v.CapKRW, CapAction: VPSCapNotify}, state.Applied)
	f.vpsReport(VPSReport{Server: "edge-1", Action: VPSCapped, At: uint64(at), Cap: over}, f.node, state.ConditionFailed)
	cat, _ = f.p.VPS(f.s)
	f.apply("admin", "set-vps-node-cap", cat.Revision, VPSServerCap{Name: "edge-1", CapKRW: v.CapKRW}, state.Applied)
	f.vpsReport(VPSReport{Server: "edge-1", Action: VPSCapped, At: uint64(at), Cap: over}, f.node, state.Applied)
	cat, _ = f.p.VPS(f.s)
	v, _ = cat.Server("edge-1")
	if v.Phase != VPSStopping || v.CapStop == nil || *v.CapStop != *over || v.StopAfter != at+VPSCapDNSWait {
		t.Fatalf("cap stopping = %+v", v)
	}
	f.vpsReport(VPSReport{Server: "edge-1", Action: VPSStopped, At: uint64(v.StopAfter)}, f.node, state.Applied)
	cat, _ = f.p.VPS(f.s)
	if v, _ = cat.Server("edge-1"); v.Phase != VPSCapped {
		t.Fatalf("capped = %+v", v)
	}
	f.apply("admin", "start-vps-node", cat.Revision, VPSServerSelection{Name: "edge-1"}, state.ConditionFailed) // cap not above the projection
	f.apply("admin", "set-vps-node-cap", cat.Revision, VPSServerCap{Name: "edge-1", CapKRW: 0}, state.Invalid)
	f.apply("admin", "set-vps-node-cap", cat.Revision, VPSServerCap{Name: "edge-1", CapKRW: over.ProjectedKRW}, state.Applied)
	cat, _ = f.p.VPS(f.s)
	f.apply("admin", "start-vps-node", cat.Revision, VPSServerSelection{Name: "edge-1"}, state.ConditionFailed) // equal is not above
	f.apply("admin", "set-vps-node-cap", cat.Revision, VPSServerCap{Name: "edge-1", CapKRW: over.ProjectedKRW + 1}, state.Applied)
	cat, _ = f.p.VPS(f.s)
	f.apply("admin", "start-vps-node", cat.Revision, VPSServerSelection{Name: "edge-1"}, state.Applied)
	f.vpsReport(VPSReport{Server: "edge-1", Action: VPSStarted, At: uint64(v.StopAfter + 1)}, f.node, state.Applied)
	cat, _ = f.p.VPS(f.s)
	if v, _ := cat.Server("edge-1"); v.Phase != VPSRunning || v.CapStop == nil {
		t.Fatalf("restarted after cap = %+v", v)
	}
	if !over.Cleared(at+40*24*3600, over.CapKRW) {
		t.Fatal("a new month does not clear the cap stop")
	}

	// node remove: closure proof, then a configuration without edge-1.
	plan, err := f.p.nodeRemovalPlan(f.s, "edge-1")
	if err != nil {
		t.Fatal(err)
	}
	f.apply("admin", "remove-node", plan.Expected, NodeLifecycleChange{ID: "edge-1", Operation: "remove-edge", Epoch: plan.Epoch}, state.Applied)
	if d, err = f.p.Members(f.s); err != nil {
		t.Fatal(err)
	}
	topology, _ := d.Topology()
	node, _ := topology.Node("edge-1")
	proof := lifecycle.Proof{Cluster: d.Cluster, Node: "edge-1", Operation: node.Pending.ID, Generation: node.Generation, Revision: node.Pending.Revision, ConfigurationIndex: topology.Configuration().Index, Closed: true}
	proof.Signature = ed25519.Sign(private, lifecycle.ProofBytes(proof))
	step(d.ObserveNode(proof))
	step(d.DispatchRemoval("remove-edge", d.Revision, base+1, akey))
	step(d.InstallConfiguration(lifecycle.Configuration{Index: base + 2, Members: []lifecycle.Member{a}}))
	if !d.Gone("edge-1") {
		t.Fatal("edge-1 not removed")
	}
	f.injectMembers(t, d)
	f.apply("admin", "delete-vps-node", cat.Revision, VPSServerSelection{Name: "edge-1"}, state.Applied)
	f.vpsReport(VPSReport{Server: "edge-1", Action: VPSDeleted}, f.node, state.Applied)
}

func (f *nodeStorageFixture) memberDispatch(node string, want state.Code) {
	f.t.Helper()
	f.next++
	d, _ := f.p.Members(f.s)
	e, _ := d.Entry(node)
	r := MemberReport{Schema: 1, Cluster: f.p.Cluster, Reporter: [32]byte(f.node.Public().(ed25519.PublicKey)), Action: "dispatch", Node: node, JobID: e.Job.Pending.ID, ConfigurationIndex: f.s.Index(),
		Expected: e.Revision, Epoch: f.s.ModuleEpoch(), RequestID: fmt.Sprintf("dispatch-%d", f.next), RootRevision: f.s.Object(MembersKey).Revision}
	r.Signature = ed25519.Sign(f.node, MemberReportBytes(r))
	cmd, err := r.Command()
	if err != nil {
		f.t.Fatal(err)
	}
	n, result, err := state.ApplyAdmitted(f.s, f.s.Index()+1, cmd, f.p.Validate, f.p.Reduce, f.p.AdmitModule)
	if err != nil || result.Code != want {
		f.t.Fatal("dispatch", result.Code, want, err)
	}
	f.s = n
}

func (f *nodeStorageFixture) injectMembers(t *testing.T, d membership.Directory) {
	t.Helper()
	writes, code := f.p.memberCheckpoint(f.s, d)
	if code != state.Applied {
		t.Fatal(code)
	}
	f.next++
	cmd := state.Command{Kind: state.Module, Actor: "anchor", Epoch: f.s.ModuleEpoch(), RequestID: fmt.Sprintf("mock-members-%d", f.next), Key: MembersKey, Expected: f.s.Object(MembersKey).Revision, Value: "fixture"}
	next, result, err := state.ApplyReduced(f.s, f.s.Index()+1, cmd, f.p.Validate, func(state.State, state.Command) (map[string][]byte, state.Code) { return writes, state.Applied })
	if err != nil || result.Code != state.Applied {
		t.Fatal("members checkpoint", result, err)
	}
	f.s = next
}

var testVPSBuild = &VPSBuild{OS: "linux", Arch: "amd64", SHA256: [32]byte{1}}

func (f *nodeStorageFixture) memberEnroll(peer config.Peer, source string, private ed25519.PrivateKey, want state.Code) {
	f.t.Helper()
	f.next++
	d, _ := f.p.Members(f.s)
	r := MemberReport{Schema: 1, Cluster: f.p.Cluster, Reporter: [32]byte(private.Public().(ed25519.PublicKey)), Action: "vps-enroll", Node: peer.ID, Peer: peer, Source: source,
		Expected: d.Revision, Epoch: f.s.ModuleEpoch(), RequestID: fmt.Sprintf("enroll-%d", f.next), RootRevision: f.s.Object(MembersKey).Revision}
	r.Signature = ed25519.Sign(private, MemberReportBytes(r))
	cmd, err := r.Command()
	if err != nil {
		f.t.Fatal(err)
	}
	n, result, err := state.ApplyAdmitted(f.s, f.s.Index()+1, cmd, f.p.Validate, f.p.Reduce, f.p.AdmitModule)
	if err != nil || result.Code != want {
		f.t.Fatal("vps-enroll", source, result.Code, want, err)
	}
	f.s = n
}
