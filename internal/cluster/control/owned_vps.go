// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/vps"
)

// OwnedVPSKey is the book of owned VPS servers: instances the operator
// already pays for at an Owned vendor (Hostinger) and attaches to the
// cluster. The cluster never buys or deletes them; it only records which
// instance is which server (devel/design/vps-hostinger.md). It is a book of
// its own, apart from the managed VPSKey servers, because the two serve
// different purposes and are never shown together (Jay 2026-11-28 14:04
// KST). The accounts stay in VPSKey; each action here checks that the
// account's vendor is Owned.
const OwnedVPSKey = "control/owned-vps"

// Owned VPS actions. attach and detach are the operator's own requests;
// the cluster never attaches or detaches by itself (Jay 2026-11-28 14:22
// KST: no automatic create or delete, manual delete always possible).
const (
	AttachOwnedVPSAction = "attach-owned-vps"
	DetachOwnedVPSAction = "detach-owned-vps"
	SetOwnedVPSAction    = "set-owned-vps"
)

// How sfcd gets onto an attached owned VPS (Jay 2026-11-28 14:23 KST: both
// ways, the operator chooses).
const (
	OwnedInstallSSH      = "ssh"      // the leader installs over SSH with the account key
	OwnedInstallManual   = "manual"   // the operator runs the shown install command
	OwnedInstallExisting = "existing" // sfcd already runs there; the server is a member
)

// What the leader does to user traffic before an owned VPS reaches its
// monthly bandwidth (design §4).
const (
	OwnedProtectExclude   = "exclude"
	OwnedProtectLowWeight = "low-weight"
)

// Owned VPS phases.
const (
	OwnedInstalling = "installing"
	OwnedRunning    = "running"
	OwnedFailed     = "failed"
)

const maxOwnedVPSServers = 64

var ownedInstanceID = regexp.MustCompile(`^[0-9]{1,20}$`)

// OwnedVPS is one attached owned VPS.
type OwnedVPS struct {
	// Name is the server (node) ID it is or becomes.
	Name       string
	Account    string
	InstanceID string
	Install    string
	// Voter: promote after joining (a separate signed promote-node). Only a
	// manual install may ask; an SSH install trusts the host key on first
	// contact.
	Voter bool `json:",omitempty"`
	// Port is the SFCP port a new server joins with (0 for existing).
	Port    uint16 `json:",omitempty"`
	Protect string
	Phase   string
	// PublicIP is the instance address the leader read from the vendor
	// (owned-vps-report checked); enrollment is accepted only from it.
	PublicIP string `json:",omitempty"`
	// Build is the leader's sfcd the server must install (ssh, manual).
	Build *VPSBuild `json:",omitempty"`
	// Invitation is the voter-signed join invitation for the enrolled key.
	Invitation *membership.Invitation `json:",omitempty"`
	// Limit is set while traffic is held off before the monthly bandwidth
	// runs out (owned-vps-report limiting, committed before anything moves).
	Limit *OwnedLimit `json:",omitempty"`
	// Restored is the last time the hold ended: by the leader once the
	// month reset (By ""), or by an operator, after whom the leader does
	// not hold the server again that month.
	Restored *OwnedRestore `json:",omitempty"`
	// Failure is the reason code of a failed phase.
	Failure string `json:",omitempty"`
	// Request is the attach-owned-vps operation ID.
	Request    string
	AttachedBy string
	AttachedAt int64
	UpdatedBy  string
	UpdatedAt  int64
}

// OwnedLimit is one traffic hold (devel/design/vps-hostinger.md §4).
type OwnedLimit struct {
	At    int64
	Month string // UTC "2006-01", the vendor's bandwidth month
	Mode  string // the server's Protect when the hold began
	// UsedMB and MonthMB are this month's use and allowance as judged;
	// ReachAt is when the use would reach the allowance at the current
	// rate (0 = already over).
	UsedMB, MonthMB, ReachAt int64
}

func (l OwnedLimit) valid() bool {
	return l.At > 0 && l.Month == OwnedMonthOf(time.Unix(l.At, 0)) && (l.Mode == OwnedProtectExclude || l.Mode == OwnedProtectLowWeight) &&
		l.UsedMB >= 0 && l.MonthMB > 0 && (l.ReachAt == 0 || l.ReachAt >= l.At)
}

// OwnedRestore is the end of a hold.
type OwnedRestore struct {
	At    int64
	Month string
	By    string `json:",omitempty"`
}

func (r OwnedRestore) valid() bool {
	return r.At > 0 && ownedMonth.MatchString(r.Month) && (r.By == "" || validVPSUser(r.By))
}

var ownedMonth = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}$`)

// OwnedMonthOf is the bandwidth month of t (UTC; the vendor resets on the
// 1st).
func OwnedMonthOf(t time.Time) string { return t.UTC().Format("2006-01") }

func (v OwnedVPS) valid() bool {
	install := v.Install == OwnedInstallSSH || v.Install == OwnedInstallManual || v.Install == OwnedInstallExisting
	protect := v.Protect == OwnedProtectExclude || v.Protect == OwnedProtectLowWeight
	phase := v.Phase == OwnedInstalling || v.Phase == OwnedRunning || v.Phase == OwnedFailed
	existing := v.Install == OwnedInstallExisting
	return lifecycle.ValidID(v.Name) && v.Name != "genesis" && vps.ValidAccountName(v.Account) && ownedInstanceID.MatchString(v.InstanceID) &&
		install && protect && phase && (!v.Voter || v.Install == OwnedInstallManual) &&
		(v.Port == 0) == existing && (v.PublicIP == "" || validVPSAddress(v.PublicIP)) &&
		(v.Build == nil || !existing && v.PublicIP != "" && v.Build.valid()) && (v.Invitation == nil || v.Build != nil) &&
		(v.Phase != OwnedRunning || v.PublicIP != "" && (existing || v.Invitation != nil)) &&
		(v.Limit == nil || v.Limit.valid()) && (v.Restored == nil || v.Restored.valid()) &&
		(v.Phase == OwnedFailed) == (v.Failure != "") && len(v.Failure) <= 64 &&
		v.Request != "" && len(v.Request) <= 128 && validVPSUser(v.AttachedBy) && validVPSUser(v.UpdatedBy) &&
		v.AttachedAt > 0 && v.UpdatedAt >= v.AttachedAt
}

// OwnedVPSCatalog is the checkpoint under OwnedVPSKey.
type OwnedVPSCatalog struct {
	Schema   uint8
	Cluster  [32]byte
	Revision uint64
	Servers  []OwnedVPS `json:",omitempty"`
}

func (c OwnedVPSCatalog) validate(cluster [32]byte) error {
	if c.Schema != 1 || c.Cluster != cluster || c.Revision == 0 || len(c.Servers) > maxOwnedVPSServers {
		return ErrCatalog
	}
	last := ""
	instances := map[[2]string]bool{}
	for _, v := range c.Servers {
		key := [2]string{v.Account, v.InstanceID}
		if !v.valid() || v.Name <= last || instances[key] {
			return ErrCatalog
		}
		instances[key] = true
		last = v.Name
	}
	return nil
}

// Server returns the owned VPS named name.
func (c OwnedVPSCatalog) Server(name string) (OwnedVPS, bool) {
	i := slices.IndexFunc(c.Servers, func(v OwnedVPS) bool { return v.Name == name })
	if i < 0 {
		return OwnedVPS{}, false
	}
	return c.Servers[i], true
}

// TrafficHolds maps each owned VPS under a traffic hold to the hold's mode
// (OwnedProtectExclude or OwnedProtectLowWeight). Ingress reads it from the
// committed catalog, so every gateway changes together (§4).
func (c OwnedVPSCatalog) TrafficHolds() map[string]string {
	holds := map[string]string{}
	for _, v := range c.Servers {
		if v.Limit != nil && v.Phase == OwnedRunning {
			holds[v.Name] = v.Limit.Mode
		}
	}
	return holds
}

// OwnedVPSAttach is attach-owned-vps's payload. Protect "" is exclude.
type OwnedVPSAttach struct {
	Name       string
	Account    string
	InstanceID string
	Install    string
	Voter      bool   `json:",omitempty"`
	Port       uint16 `json:",omitempty"`
	Protect    string `json:",omitempty"`
}

// OwnedVPSSelection is detach-owned-vps's payload. Detaching removes only
// the record: the VPS keeps running at the vendor, and a joined server
// leaves the cluster through node remove.
type OwnedVPSSelection struct{ Name string }

// OwnedVPSSet is set-owned-vps's payload: the protection mode, and/or
// Restore to end a traffic hold now (the leader then leaves the server be
// until next month).
type OwnedVPSSet struct {
	Name    string
	Protect string `json:",omitempty"`
	Restore bool   `json:",omitempty"`
}

func ownedVendor(id string) bool {
	_, ok := vps.LookupOwned(id)
	return ok
}

// OwnedVPS reads the owned VPS catalog (an empty one before the first write).
func (p Policy) OwnedVPS(s state.State) (OwnedVPSCatalog, error) {
	c := OwnedVPSCatalog{Schema: 1, Cluster: p.Cluster}
	raw, revision, err := readCheckpoint(s, OwnedVPSKey, p.Cluster, p.TrustRoot)
	if err != nil {
		return c, err
	}
	if raw == nil {
		return c, nil
	}
	if canonical(raw, &c) != nil || c.Revision != revision || c.validate(p.Cluster) != nil {
		return c, ErrCatalog
	}
	return c, nil
}

func (p Policy) reduceOwnedVPS(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	if cmd.Key == OwnedVPSKey && cmd.Kind == state.ModuleReport {
		return p.reduceOwnedVPSReport(s, cmd)
	}
	if cmd.Key != OwnedVPSKey || cmd.Kind != state.Module {
		return nil, state.Forbidden
	}
	p, err := p.Current(s)
	if err != nil {
		return nil, state.Invalid
	}
	users, err := p.Catalog(s)
	if err != nil {
		return nil, state.Invalid
	}
	op, err := p.Operation(users, cmd, false)
	if err != nil || p.authorizeCertificate(users, op) != nil {
		return nil, state.Forbidden
	}
	c, err := p.OwnedVPS(s)
	if err != nil {
		return nil, state.Invalid
	}
	if op.Change.Expected != c.Revision {
		return nil, state.ConditionFailed
	}
	switch op.Change.Action {
	case AttachOwnedVPSAction:
		return p.attachOwnedVPS(s, c, op)
	case DetachOwnedVPSAction:
		var q OwnedVPSSelection
		if canonical(op.Change.Payload, &q) != nil || !lifecycle.ValidID(q.Name) {
			return nil, state.Invalid
		}
		if _, ok := c.Server(q.Name); !ok {
			return nil, state.ConditionFailed
		}
		c.Servers = slices.DeleteFunc(c.Servers, func(v OwnedVPS) bool { return v.Name == q.Name })
	case SetOwnedVPSAction:
		var q OwnedVPSSet
		if canonical(op.Change.Payload, &q) != nil || !lifecycle.ValidID(q.Name) || q.Protect == "" && !q.Restore ||
			q.Protect != "" && q.Protect != OwnedProtectExclude && q.Protect != OwnedProtectLowWeight {
			return nil, state.Invalid
		}
		i := slices.IndexFunc(c.Servers, func(v OwnedVPS) bool { return v.Name == q.Name })
		if i < 0 || q.Restore && c.Servers[i].Limit == nil {
			return nil, state.ConditionFailed
		}
		v := &c.Servers[i]
		at := max(op.At, v.UpdatedAt)
		if q.Protect != "" {
			v.Protect = q.Protect
		}
		if q.Restore {
			v.Restored, v.Limit = &OwnedRestore{At: at, Month: v.Limit.Month, By: op.Session.User}, nil
		}
		v.UpdatedBy, v.UpdatedAt = op.Session.User, at
	default:
		return nil, state.Forbidden
	}
	return p.writeOwnedVPS(s, c)
}

func (p Policy) attachOwnedVPS(s state.State, c OwnedVPSCatalog, op UserOperation) (map[string][]byte, state.Code) {
	var q OwnedVPSAttach
	if canonical(op.Change.Payload, &q) != nil || !lifecycle.ValidID(q.Name) || !vps.ValidAccountName(q.Account) || !ownedInstanceID.MatchString(q.InstanceID) {
		return nil, state.Invalid
	}
	if q.Protect == "" {
		q.Protect = OwnedProtectExclude
	}
	// Every attach starts installing: the leader first reads the instance
	// from the vendor (owned-vps-report checked).
	v := OwnedVPS{Name: q.Name, Account: q.Account, InstanceID: q.InstanceID, Install: q.Install, Voter: q.Voter, Port: q.Port, Protect: q.Protect,
		Phase: OwnedInstalling, Request: op.RequestID, AttachedBy: op.Session.User, AttachedAt: op.At, UpdatedBy: op.Session.User, UpdatedAt: op.At}
	if !v.valid() {
		return nil, state.Invalid
	}
	accounts, err := p.VPS(s)
	if err != nil {
		return nil, state.Invalid
	}
	account, ok := accounts.Account(q.Account)
	if !ok || !ownedVendor(account.Vendor) || len(c.Servers) >= maxOwnedVPSServers {
		return nil, state.ConditionFailed
	}
	// An SSH install puts the account key on the VPS, so the account must
	// have one.
	if v.Install == OwnedInstallSSH && account.Credential.SSHPublic == "" {
		return nil, state.ConditionFailed
	}
	if slices.ContainsFunc(c.Servers, func(x OwnedVPS) bool {
		return x.Name == q.Name || x.Account == q.Account && x.InstanceID == q.InstanceID
	}) || slices.ContainsFunc(accounts.Servers, func(x VPSServer) bool { return x.Name == q.Name }) {
		return nil, state.ConditionFailed
	}
	members, err := p.Members(s)
	if err != nil {
		return nil, state.Invalid
	}
	// existing binds a server that already joined; the other two make a new
	// one, so the name must be free (and not a removed server's).
	_, member := members.Entry(q.Name)
	if member != (v.Install == OwnedInstallExisting) || v.Install != OwnedInstallExisting && members.Gone(q.Name) {
		return nil, state.ConditionFailed
	}
	c.Servers = append(c.Servers, v)
	slices.SortFunc(c.Servers, func(x, y OwnedVPS) int { return strings.Compare(x.Name, y.Name) })
	return p.writeOwnedVPS(s, c)
}

func (p Policy) writeOwnedVPS(s state.State, c OwnedVPSCatalog) (map[string][]byte, state.Code) {
	c.Revision++
	if c.validate(p.Cluster) != nil {
		return nil, state.Invalid
	}
	raw, err := json.Marshal(c)
	if err != nil || len(raw) > 1<<20 {
		return nil, state.Invalid
	}
	return writeCheckpoint(s, OwnedVPSKey, p.Cluster, p.TrustRoot, c.Revision, raw)
}

// ownedVPSBook is the OwnedVPSKey Raft book (see book.go).
var ownedVPSBook = Book{
	Key:     OwnedVPSKey,
	Actions: []string{AttachOwnedVPSAction, DetachOwnedVPSAction, SetOwnedVPSAction},
	Reduce:  Policy.reduceOwnedVPS,
	AdmitReport: func(p Policy, s state.State, cmd state.Command) error {
		_, err := p.ownedVPSReport(s, cmd)
		return err
	},
	ReportOnly: true,
}

// OwnedVPSQuery is the owned-vps read. Status also asks the leader for its
// memory of the vendor readings (OwnedVPSStatus).
type OwnedVPSQuery struct {
	Status bool `json:",omitempty"`
	// Instances names an Owned-vendor account whose VMs the leader lists
	// for the attach picker ("" = none).
	Instances string `json:",omitempty"`
}

// OwnedVPSInstance is one VM in an account, as the vendor reports it now,
// for picking what to attach. Attached is the owned VPS record using it
// ("" = free).
type OwnedVPSInstance struct {
	ID, Plan, Zone, PublicIP, Image string
	Status                          string // pending, active, working, off, error
	ExpiresAt                       int64  `json:",omitempty"` // subscription end (0 = not read)
	Attached                        string `json:",omitempty"`
}

// OwnedVPSPage is the owned VPS screen: only Owned-vendor accounts and the
// attached servers. Managed accounts and servers are on VPSPage only.
type OwnedVPSPage struct {
	Revision        uint64
	AccountRevision uint64
	Accounts        []VPSPublicAccount
	Servers         []OwnedVPS
}

// OwnedVPSPage reads the owned VPS screen for a system administrator.
func (p Policy) OwnedVPSPage(s state.State, session access.Session, at int64, q OwnedVPSQuery) (OwnedVPSPage, error) {
	if p.VPSAllowed(s, session, at, "owned-vps") != nil {
		return OwnedVPSPage{}, access.ErrDenied
	}
	accounts, err := p.VPS(s)
	if err != nil {
		return OwnedVPSPage{}, err
	}
	if q.Instances != "" {
		if a, ok := accounts.Account(q.Instances); !ok || !ownedVendor(a.Vendor) {
			return OwnedVPSPage{}, access.ErrInvalid
		}
	}
	c, err := p.OwnedVPS(s)
	if err != nil {
		return OwnedVPSPage{}, err
	}
	out := OwnedVPSPage{Revision: c.Revision, AccountRevision: accounts.Revision, Accounts: []VPSPublicAccount{}, Servers: append([]OwnedVPS{}, c.Servers...)}
	for _, a := range accounts.Accounts {
		if ownedVendor(a.Vendor) {
			out.Accounts = append(out.Accounts, a.Public())
		}
	}
	return out, nil
}
