// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"context"
	"crypto/sha256"
	"errors"
	"slices"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/internal/vps"
)

// VPS servers in sfcd's shape (devel/design/vps-nodes.md). The fake keeps
// the public page and moves a server to the phase sfcd's reducer writes
// (stopping, starting, deleting, creating); the leader's work after that
// (provider calls, reports) is not modeled. Seeded from Fixture.VPS.

// FixtureVPS seeds the VPS page, the leader's cost watch (nil Status =
// unavailable) and what each account's vendor sells (no entry =
// unavailable).
type FixtureVPS struct {
	Accounts []control.VPSPublicAccount
	Servers  []control.VPSServer
	Status   *control.VPSStatus
	Offers   map[string]control.VPSOffer
}

type vpsFakeState struct {
	page   control.VPSPage
	status *control.VPSStatus
	offers map[string]control.VPSOffer
}

func (w *world) seedVPS(f Fixture) {
	w.vps = vpsFakeState{page: control.VPSPage{Revision: 1, Accounts: []control.VPSPublicAccount{}, Servers: []control.VPSServer{}}, offers: map[string]control.VPSOffer{}}
	if f.VPS == nil {
		return
	}
	w.vps.page.Accounts = append(w.vps.page.Accounts, f.VPS.Accounts...)
	w.vps.page.Servers = append(w.vps.page.Servers, f.VPS.Servers...)
	w.vps.status = f.VPS.Status
	for k, v := range f.VPS.Offers {
		w.vps.offers[k] = v
	}
}

func (c *fakeConn) QueryVPS(ctx context.Context) (control.VPSPage, error) {
	if err := c.adminOnly(ctx, "vps"); err != nil {
		return control.VPSPage{}, err
	}
	defer c.unlock()
	p := c.f.w.vps.page
	return control.VPSPage{Revision: p.Revision, Accounts: slices.Clone(p.Accounts), Servers: slices.Clone(p.Servers)}, nil
}

func (c *fakeConn) QueryVPSStatus(ctx context.Context) (control.VPSStatus, error) {
	if err := c.adminOnly(ctx, "vps"); err != nil {
		return control.VPSStatus{}, err
	}
	defer c.unlock()
	if c.f.w.vps.status == nil {
		return control.VPSStatus{}, fail("vps", CodeUnavailable, "leader")
	}
	return *c.f.w.vps.status, nil
}

func (c *fakeConn) QueryVPSOffer(ctx context.Context, q control.VPSOfferQuery) (control.VPSOffer, error) {
	if !q.Valid() || !vps.ValidAccountName(q.Account) {
		return control.VPSOffer{}, fail("vps", CodeInvalid, "offer query")
	}
	if err := c.adminOnly(ctx, "vps"); err != nil {
		return control.VPSOffer{}, err
	}
	defer c.unlock()
	o, ok := c.f.w.vps.offers[q.Account]
	if !ok {
		return control.VPSOffer{}, fail("vps", CodeUnavailable, "vendor")
	}
	return o, nil
}

func (c *fakeConn) SealVPSCredential(ctx context.Context, in userauth.VPSCredentialInput) (vps.SealedCredential, error) {
	const m = "vps-credential"
	if in.Request == "" || !vps.ValidAccountName(in.Account) || len(in.AccessKey) == 0 || len(in.AccessKey) > 256 || len(in.SecretKey) == 0 || len(in.SecretKey) > 256 {
		return vps.SealedCredential{}, fail(m, CodeInvalid, "credential input")
	}
	if err := c.adminOnly(ctx, m); err != nil {
		return vps.SealedCredential{}, err
	}
	defer c.unlock()
	if string(in.SecretKey) == "rejected" {
		return vps.SealedCredential{}, fail(m, CodeUnavailable, "vendor refused the key")
	}
	hint := string(in.AccessKey)
	if len(hint) > 4 {
		hint = hint[len(hint)-4:]
	}
	box := sha256.Sum256(append(append([]byte(in.Request+"\x00"), in.AccessKey...), in.SecretKey...))
	return vps.SealedCredential{Schema: 1, Cluster: c.f.w.cluster, Account: in.Account, Request: in.Request, KeyID: box, Box: box[:], Hint: hint,
		SSHPublic: "ssh-ed25519 AAAAfake sfc-" + in.Account}, nil
}

var errVPSPhase = errors.New("vps phase")

// applyVPS models the reducer's first step of each VPS action.
func (c *fakeConn) applyVPS(op UserOperation, actor string) error {
	w := c.f.w
	if !w.admin(actor) {
		return errForbidden
	}
	p := &w.vps.page
	if op.Change.Expected != p.Revision {
		return errCAS
	}
	now := c.f.now().Unix()
	server := func(name string) (*control.VPSServer, error) {
		i := slices.IndexFunc(p.Servers, func(v control.VPSServer) bool { return v.Name == name })
		if i < 0 {
			return nil, errors.New("no such server")
		}
		return &p.Servers[i], nil
	}
	switch op.Change.Action {
	case ActionPutVPSAccount:
		var q control.VPSAccountPut
		if decodePayload(op.Change.Payload, &q) != nil || !vps.ValidAccountName(q.Name) || q.OverageKRWPerGB < 0 || q.OverageKRWPerGB > control.MaxOverageKRWPerGB || !vps.ValidGuard(q.Guard.WindowMin, q.Guard.AverageMin) {
			return errors.New("payload")
		}
		i := slices.IndexFunc(p.Accounts, func(a control.VPSPublicAccount) bool { return a.Name == q.Name })
		if i < 0 {
			if q.Credential == nil {
				return errors.New("a new account needs a credential")
			}
			p.Accounts = append(p.Accounts, control.VPSPublicAccount{Name: q.Name, Vendor: q.Vendor, AddedBy: actor, AddedAt: now})
			slices.SortFunc(p.Accounts, func(a, b control.VPSPublicAccount) int { return cmpString(a.Name, b.Name) })
			i = slices.IndexFunc(p.Accounts, func(a control.VPSPublicAccount) bool { return a.Name == q.Name })
		}
		a := &p.Accounts[i]
		a.OverageKRWPerGB, a.Guard, a.UpdatedBy, a.UpdatedAt = q.OverageKRWPerGB, q.Guard, actor, now
		if q.Credential != nil {
			a.KeyHint, a.SSHPublic, a.SSHKeyID = q.Credential.Hint, q.Credential.SSHPublic, ""
		} else {
			a.SSHKeyID = q.SSHKeyID
		}
	case ActionRemoveVPSAccount:
		var q control.VPSAccountSelection
		if decodePayload(op.Change.Payload, &q) != nil {
			return errors.New("payload")
		}
		if slices.ContainsFunc(p.Servers, func(v control.VPSServer) bool { return v.Account == q.Name }) {
			return errVPSPhase
		}
		n := len(p.Accounts)
		p.Accounts = slices.DeleteFunc(p.Accounts, func(a control.VPSPublicAccount) bool { return a.Name == q.Name })
		if len(p.Accounts) == n {
			return errors.New("no such account")
		}
	case ActionCreateVPSNode:
		var q control.VPSServerCreate
		if decodePayload(op.Change.Payload, &q) != nil || !q.Valid() {
			return errors.New("payload")
		}
		if _, err := server(q.Name); err == nil {
			return errVPSPhase
		}
		p.Servers = append(p.Servers, control.VPSServer{Name: q.Name, Account: q.Account, Zone: q.Zone, Image: q.Image, Flavor: q.Flavor, Script: q.Script, SSHKeys: q.SSHKeys,
			CapKRW: q.CapKRW, CapAction: q.CapAction, Voter: q.Voter, Port: q.Port, Request: op.RequestID, CreatedBy: actor, CreatedAt: now, Phase: control.VPSCreating, PhaseAt: now})
		slices.SortFunc(p.Servers, func(a, b control.VPSServer) int { return cmpString(a.Name, b.Name) })
	case ActionStopVPSNode:
		var q control.VPSServerStop
		if decodePayload(op.Change.Payload, &q) != nil || q.DNSWaitSeconds < 0 || q.DNSWaitSeconds > control.MaxVPSDNSWait {
			return errors.New("payload")
		}
		v, err := server(q.Name)
		if err != nil {
			return err
		}
		if v.Phase != control.VPSRunning {
			return errVPSPhase
		}
		v.Phase, v.PhaseAt, v.PowerRequest, v.StopAfter = control.VPSStopping, now, op.RequestID, now+q.DNSWaitSeconds
	case ActionStartVPSNode, ActionDeleteVPSNode:
		var q control.VPSServerSelection
		if decodePayload(op.Change.Payload, &q) != nil {
			return errors.New("payload")
		}
		v, err := server(q.Name)
		if err != nil {
			return err
		}
		if op.Change.Action == ActionDeleteVPSNode {
			if v.Phase == control.VPSDeleting {
				return errVPSPhase
			}
			v.Phase, v.PhaseAt, v.DeleteRequest = control.VPSDeleting, now, op.RequestID
			break
		}
		if v.Phase != control.VPSStopped && v.Phase != control.VPSCapped || v.Phase == control.VPSCapped && v.CapStop != nil && !v.CapStop.Cleared(now, v.CapKRW) {
			return errVPSPhase
		}
		v.Phase, v.PhaseAt, v.PowerRequest, v.StopAfter = control.VPSStarting, now, op.RequestID, 0
	case ActionSetVPSNodeCap:
		var q control.VPSServerCap
		if decodePayload(op.Change.Payload, &q) != nil || q.CapKRW <= 0 || q.CapAction != control.VPSCapStopAction && q.CapAction != control.VPSCapNotify {
			return errors.New("payload")
		}
		v, err := server(q.Name)
		if err != nil {
			return err
		}
		if v.CapKRW == q.CapKRW && v.CapAction == q.CapAction {
			return errCAS
		}
		v.CapKRW, v.CapAction = q.CapKRW, q.CapAction
	default:
		return errors.New("action")
	}
	p.Revision++
	return nil
}

func cmpString(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// DefaultVPSFixture: account main (iwinv) with a running server, a server
// stopped for its cap and one being created; the cost watch has an hour of
// readings for the running one.
func DefaultVPSFixture() *FixtureVPS {
	const at = 1795600000
	month := control.VPSCapStop{At: at - 86400, Month: "2026-11", CapKRW: 20000, SoFarKRW: 20000, ProjectedKRW: 31400}
	return &FixtureVPS{
		Accounts: []control.VPSPublicAccount{{Name: "main", Vendor: "iwinv", OverageKRWPerGB: 10, OverageTiers: vps.IwinvVendor().OverageTiers, KeyHint: "3F2A", SSHPublic: "ssh-ed25519 AAAAfake sfc-main", AddedBy: "admin", AddedAt: at - 30*86400, UpdatedBy: "admin", UpdatedAt: at - 30*86400}},
		Servers: []control.VPSServer{
			{Name: "vps-busan-1", Account: "main", Zone: "KR2", Image: "ubuntu-2404", Flavor: "ss1-c2m4", Script: "sfc-enroll", CapKRW: 20000, Port: 7443, Request: "op-busan", CreatedBy: "admin", CreatedAt: at - 7*86400,
				Phase: control.VPSCapped, PhaseAt: at - 86400 + 400, CapStop: &month, InstanceID: "i-busan", PublicIP: "198.51.100.9"},
			{Name: "vps-seoul-1", Account: "main", Zone: "KR1", Image: "ubuntu-2404", Flavor: "ss1-c2m4", Script: "sfc-enroll", CapKRW: 30000, Port: 7443, Request: "op-seoul-1", CreatedBy: "admin", CreatedAt: at - 24*86400,
				Phase: control.VPSRunning, PhaseAt: at - 24*86400 + 600, InstanceID: "i-seoul-1", PublicIP: "203.0.113.21"},
			{Name: "vps-seoul-3", Account: "main", Zone: "KR1", Image: "ubuntu-2404", Flavor: "ss1-c1m2", Script: "sfc-enroll", CapKRW: 15000, CapAction: control.VPSCapNotify, Port: 7443, Request: "op-seoul-3", CreatedBy: "admin", CreatedAt: at - 600,
				Phase: control.VPSCreating, PhaseAt: at - 600},
		},
		Status: &control.VPSStatus{Leader: "node-a",
			Servers: []control.VPSServerStatus{{Name: "vps-seoul-1", UpdatedAt: at, CapKRW: 30000, SoFarKRW: 19800, ProjectedKRW: 24600, BaseSoFarKRW: 19800, BaseMonthKRW: 22000,
				UsedGB: 412, ProjectedGB: 460, RecentMB: 412, Judgeable: true,
				IncludedGB: 20, IncludedPeriod: "DAY", IncludedMonthGB: 500, IncludedMaxGB: 600, TodayMB: 14 * 1024,
				Daily: []control.VPSTrafficDay{{Day: "2026-11-21", MB: 16 * 1024}, {Day: "2026-11-22", MB: 18 * 1024}, {Day: "2026-11-23", MB: 22 * 1024},
					{Day: "2026-11-24", MB: 19 * 1024}, {Day: "2026-11-25", MB: 17 * 1024}, {Day: "2026-11-26", MB: 21 * 1024}, {Day: "2026-11-27", MB: 14 * 1024}},
				Guard: &control.VPSGuardStatus{At: at, RateMbps: 42, PrevMbps: 38, AverageMbps: 35, ForecastGB: 6.6, PatternGB: 4.1, PatternDays: 12, PatternUsed: true,
					MonthGB: 412, RemainingGB: 160, SoonAt: at + 9*3600}}},
			Accounts: []control.VPSAccountStatus{{Name: "main", BillKRW: 39900, OursKRW: 39800, UpdatedAt: at}}},
		Offers: map[string]control.VPSOffer{"main": {Account: "main", At: at,
			Zones:   []vps.Zone{{ID: "KR1", Name: "서울", Usable: true}, {ID: "KR2", Name: "부산", Usable: true}},
			Images:  []vps.Image{{ID: "ubuntu-2404", Name: "Ubuntu 24.04 LTS", Kind: "os_linux", OS: "UBUNTU", Linux: true, Zones: []string{"KR1", "KR2"}}},
			Flavors: []vps.Flavor{{ID: "ss1-c1m2", Name: "ss1.c1m2", VCPU: 1, MemoryMiB: 2048, DiskGB: 25, Full: vps.Price{KRW: 11000, Per: "month"}}, {ID: "ss1-c2m4", Name: "ss1.c2m4", VCPU: 2, MemoryMiB: 4096, DiskGB: 50, Full: vps.Price{KRW: 22000, Per: "month"}}},
			Scripts: []vps.Script{{ID: "sfc-enroll", Name: "sfcli enroll"}}}},
	}
}

// SetVPSPhase moves a VPS server to phase as the leader's reports would
// ("" removes it, as vps-report deleted does). Tests only.
func (f *Fake) SetVPSPhase(name, phase string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := &f.w.vps.page
	i := slices.IndexFunc(p.Servers, func(v control.VPSServer) bool { return v.Name == name })
	if i < 0 {
		return
	}
	if phase == "" {
		p.Servers = slices.Delete(p.Servers, i, i+1)
	} else {
		p.Servers[i].Phase, p.Servers[i].PhaseAt = phase, f.now().Unix()
	}
	p.Revision++
}
