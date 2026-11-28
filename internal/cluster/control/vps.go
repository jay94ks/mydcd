// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"net/netip"
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

// VPSKey holds the cluster's VPS provider accounts (devel/design/
// vps-nodes.md). Only the sealed credential is stored; the plain key pair
// is never in Raft.
const VPSKey = "control/vps"

const maxVPSAccounts = 32

// MaxOverageKRWPerGB bounds the user-entered traffic price.
const MaxOverageKRWPerGB = 1_000_000

// VPSAccount is one provider account.
type VPSAccount struct {
	Name            string
	Vendor          string
	OverageKRWPerGB int64
	Credential      vps.SealedCredential
	// SSHKeyID is the vendor's ID of Credential.SSHPublic once the user
	// registered it there; "" until then. A new credential (rotate-key)
	// brings a new SSH key and clears it.
	SSHKeyID string `json:",omitempty"`
	// Guard is the early traffic guard's settings (§6a; zero = defaults).
	Guard     VPSGuard `json:",omitzero"`
	AddedBy   string
	AddedAt   int64
	UpdatedBy string
	UpdatedAt int64
}

// VPSGuard is an account's early traffic guard settings: the forecast
// window and long average in minutes (0 = default 5 and 60) and whether the
// month's pattern is left out (Jay 2026-11-27: all changeable).
type VPSGuard struct {
	WindowMin  int  `json:",omitempty"`
	AverageMin int  `json:",omitempty"`
	PatternOff bool `json:",omitempty"`
}

func (g VPSGuard) valid() bool { return vps.ValidGuard(g.WindowMin, g.AverageMin) }

// Settings is the guard's view of g.
func (g VPSGuard) Settings() vps.GuardSettings {
	return vps.GuardSettings{WindowMin: g.WindowMin, AverageMin: g.AverageMin, Pattern: !g.PatternOff}
}

// VPSPublicAccount is an account as reads show it: no ciphertext.
type VPSPublicAccount struct {
	Name            string
	Vendor          string
	OverageKRWPerGB int64
	// OverageTiers is the vendor's published overage price; when present
	// it is used instead of OverageKRWPerGB. Not stored: read from the
	// vendor.
	OverageTiers []vps.OverageTier `json:",omitempty"`
	KeyHint      string            // last four characters of the access key
	SSHPublic    string            `json:",omitempty"` // register this with the vendor
	SSHKeyID     string            `json:",omitempty"`
	Guard        VPSGuard          `json:",omitzero"`
	AddedBy      string
	AddedAt      int64
	UpdatedBy    string
	UpdatedAt    int64
}

func (a VPSAccount) Public() VPSPublicAccount {
	v, _ := vps.Lookup(a.Vendor)
	return VPSPublicAccount{Name: a.Name, Vendor: a.Vendor, OverageKRWPerGB: a.OverageKRWPerGB, OverageTiers: v.OverageTiers, KeyHint: a.Credential.Hint, SSHPublic: a.Credential.SSHPublic, SSHKeyID: a.SSHKeyID, Guard: a.Guard, AddedBy: a.AddedBy, AddedAt: a.AddedAt, UpdatedBy: a.UpdatedBy, UpdatedAt: a.UpdatedAt}
}

// VPSCatalog is the checkpoint under VPSKey.
type VPSCatalog struct {
	Schema   uint8
	Cluster  [32]byte
	Revision uint64
	Accounts []VPSAccount
	Servers  []VPSServer `json:",omitempty"`
}

// VPSAccountPut is put-vps-account's payload. A new account needs
// Credential; an existing one keeps its credential when Credential is nil.
type VPSAccountPut struct {
	Name            string
	Vendor          string
	OverageKRWPerGB int64
	Credential      *vps.SealedCredential `json:",omitempty"`
	// SSHKeyID is replaced on every put without a credential ("" clears).
	SSHKeyID string `json:",omitempty"`
	// Guard is replaced on every put, like OverageKRWPerGB.
	Guard VPSGuard `json:",omitzero"`
}

// VPSAccountSelection is remove-vps-account's payload.
type VPSAccountSelection struct{ Name string }

// VPSServerSelection is delete-vps-node's payload.
type VPSServerSelection struct{ Name string }

// VPSServerStop is stop-vps-node's payload: DNSWaitSeconds is how long the
// leader waits after DNS is taken off (the record TTL) before shutting the
// instance down.
type VPSServerStop struct {
	Name           string
	DNSWaitSeconds int64
}

// MaxVPSDNSWait bounds the DNS wait of stop-vps-node.
const MaxVPSDNSWait = 3600

// VPSCapDNSWait is the DNS wait of a stop for the monthly cap.
const VPSCapDNSWait = 300

// VPSServerCap is set-vps-node-cap's payload: the new monthly cap in KRW
// and what the leader does when it is crossed.
type VPSServerCap struct {
	Name      string
	CapKRW    int64
	CapAction string `json:",omitempty"`
}

// What the leader does when a server crosses its monthly cap. The operator
// picks per server; stopping is the default (Jay 2026-11-27).
const (
	// VPSCapStop: take DNS off, wait VPSCapDNSWait, power off. No drain:
	// the leader cannot start one without a user's signature.
	VPSCapStopAction = ""
	// VPSCapNotify: keep running and only show the crossing.
	VPSCapNotify = "notify"
)

func validVPSCapAction(a string) bool { return a == VPSCapStopAction || a == VPSCapNotify }

// VPSCapStop records that the leader stopped a server for its monthly cap:
// the billing month (KST, "2006-01"), the cap then, and the charge so far
// and the month's projection it saw. A capped server starts again only
// with a cap above that projection, or in a later month.
type VPSCapStop struct {
	At                     int64
	Month                  string
	CapKRW                 int64
	SoFarKRW, ProjectedKRW int64
	// Reason is "" for the 10-minute projection, or VPSCapTrafficSoon when
	// the 1-minute guard expected the traffic to cross the cap within
	// 15 minutes (devel/design/vps-nodes.md §6a).
	Reason string `json:",omitempty"`
}

// VPSCapTrafficSoon is the guard's cap stop reason.
const VPSCapTrafficSoon = "traffic-soon"

func (c VPSCapStop) valid() bool {
	_, err := time.Parse("2006-01", c.Month)
	return err == nil && (c.Reason == "" || c.Reason == VPSCapTrafficSoon) && c.At > 0 && c.CapKRW > 0 && c.CapKRW <= MaxVPSCapKRW && c.SoFarKRW >= 0 && c.ProjectedKRW >= c.SoFarKRW && c.ProjectedKRW <= math.MaxInt64/2 &&
		(c.SoFarKRW > c.CapKRW || c.ProjectedKRW > c.CapKRW)
}

// request is the PowerRequest of the cap stop.
func (c VPSCapStop) request() string { return "cap-" + c.Month }

// Cleared reports whether a server capped by c may start at unix time at
// with cap capKRW: a later billing month, or a cap above the projection.
func (c VPSCapStop) Cleared(at, capKRW int64) bool {
	return vps.MonthOf(time.Unix(at, 0)) != c.Month || capKRW > c.ProjectedKRW
}

// VPSQuery reads the account list (no options yet).
type VPSQuery struct {
	// Offer, when set, asks the voter answering to read what an account's
	// vendor sells now (the "new VPS node" form). The plain page is still
	// returned with it.
	Offer *VPSOfferQuery `json:",omitempty"`
	// Status asks for the leader's live cost watch (devel/design/vps-nodes.md §7).
	Status bool `json:",omitempty"`
}

// VPSStatus is the leader's cost watch, kept in its memory only: a new
// leader reads the provider again (§3).
type VPSStatus struct {
	Leader   string
	Servers  []VPSServerStatus
	Accounts []VPSAccountStatus
}

// VPSServerStatus is one running server's month as the leader last read it.
type VPSServerStatus struct {
	Name                       string
	UpdatedAt                  int64
	CapKRW                     int64
	SoFarKRW, ProjectedKRW     int64
	BaseSoFarKRW, BaseMonthKRW int64
	TrafficSoFarKRW            int64
	TrafficMonthKRW            int64
	UsedGB, ProjectedGB        float64
	RecentMB                   int64 // traffic since the previous read
	// IncludedGB per IncludedPeriod ("MONTH" or "DAY") is the vendor's
	// free traffic, read with the instance.
	IncludedGB     int64  `json:",omitempty"`
	IncludedPeriod string `json:",omitempty"`
	// IncludedMonthGB is this month's free traffic the overage counts from
	// (a daily allowance times the days in service, at most IncludedMaxGB,
	// the vendor's monthly ceiling). TodayMB is today's use (KST), for a
	// daily allowance.
	IncludedMonthGB float64 `json:",omitempty"`
	IncludedMaxGB   int64   `json:",omitempty"`
	TodayMB         int64   `json:",omitempty"`
	// Daily is the use of the last seven days of this month (KST), oldest
	// first; days before the 1st are not read.
	Daily []VPSTrafficDay `json:",omitempty"`
	// TrafficCounting is the vendor's rule: "tx", "rx+tx" or "" (not known).
	TrafficCounting string `json:",omitempty"`
	Judgeable       bool   // readings cover an hour: a projection may stop it
	Failure         string `json:",omitempty"`
	FailureAt       int64  `json:",omitempty"`
	// Guard is the 1-minute early traffic guard (§6a), nil until the
	// server has reported a window of its own counts.
	Guard *VPSGuardStatus `json:",omitempty"`
	// Over: the month crosses the cap. It keeps running when CapAction is
	// notify, or (CapBlocked) when stopping this voter would leave the
	// cluster no failure to spare.
	Over       bool `json:",omitempty"`
	CapBlocked bool `json:",omitempty"`
}

// VPSGuardStatus is the early traffic guard's last judgement of a server.
type VPSGuardStatus struct {
	At                              int64
	RateMbps, PrevMbps, AverageMbps float64 // last window, the one before, long average
	ForecastGB                      float64 // expected over the next 21 minutes
	PatternGB                       float64 `json:",omitempty"`
	PatternDays                     int     `json:",omitempty"`
	PatternUsed                     bool    `json:",omitempty"`
	MonthGB                         float64 // vendor total plus own counts since
	RemainingGB                     float64 `json:",omitempty"` // to the cap; omitted when unlimited
	Unlimited                       bool    `json:",omitempty"` // no cap, or traffic is free
	Soon                            bool    `json:",omitempty"` // the cap is expected within 21 minutes
	SoonAt                          int64   `json:",omitempty"` // when, at the forecast pace
}

// VPSTrafficDay is one day's traffic.
type VPSTrafficDay struct {
	Day string // YYYY-MM-DD
	MB  int64
}

// VPSAccountStatus is an account's live bill against our own sum.
type VPSAccountStatus struct {
	Name      string
	BillKRW   int64 // the vendor's charge so far this month
	OursKRW   int64 // the sum of our SoFarKRW for its servers
	UpdatedAt int64
	Failure   string `json:",omitempty"`
	FailureAt int64  `json:",omitempty"`
}

// Valid checks the offer query, when there is one.
func (q VPSQuery) Valid() bool { return q.Offer == nil || q.Offer.Valid() }

// VPSOfferQuery names the account and narrows images and flavors.
type VPSOfferQuery struct {
	Account string
	Zone    string          `json:",omitempty"` // images and flavors usable in this zone
	Flavors vps.FlavorQuery // passed to the vendor's filters
}

// Valid reports whether q is a well-formed offer query.
func (q VPSOfferQuery) Valid() bool {
	f := q.Flavors
	for _, xs := range [][]string{f.Zones, f.Images, f.CoreTypes} {
		if len(xs) > 8 {
			return false
		}
		for _, x := range xs {
			if !vpsVendorID.MatchString(x) {
				return false
			}
		}
	}
	return vps.ValidAccountName(q.Account) && (q.Zone == "" || vpsVendorID.MatchString(q.Zone)) &&
		min(f.MinVCPU, f.MaxVCPU, f.MinGPU, f.MaxGPU) >= 0 && min(f.MinMemoryMiB, f.MaxMemoryMiB, f.MinDiskGB, f.MaxDiskGB) >= 0
}

// VPSOffer is what an account's vendor sells, read live by a voter. It is
// never stored: prices and stock change.
type VPSOffer struct {
	Account string
	At      int64
	Zones   []vps.Zone
	Images  []vps.Image
	Flavors []vps.Flavor
	SSHKeys []vps.SSHKey
	Scripts []vps.Script
}

// VPSPage is the "vps" read.
type VPSPage struct {
	Revision uint64
	Accounts []VPSPublicAccount
	Servers  []VPSServer
}

func validVPSUser(u string) bool { return u != "" && len(u) <= 128 }

func (c VPSCatalog) validate(cluster [32]byte) error {
	if c.Schema != 1 || c.Cluster != cluster || c.Revision == 0 || len(c.Accounts) > maxVPSAccounts {
		return ErrCatalog
	}
	last := ""
	for _, a := range c.Accounts {
		if !vps.ValidAccountName(a.Name) || a.Name <= last || !knownVendor(a.Vendor) || a.OverageKRWPerGB < 0 || a.OverageKRWPerGB > MaxOverageKRWPerGB || !a.Guard.valid() ||
			a.Credential.Validate() != nil || a.Credential.Cluster != cluster || a.Credential.Account != a.Name ||
			!validVPSUser(a.AddedBy) || !validVPSUser(a.UpdatedBy) || a.AddedAt <= 0 || a.UpdatedAt < a.AddedAt {
			return ErrCatalog
		}
		last = a.Name
	}
	if len(c.Servers) > maxVPSServers {
		return ErrCatalog
	}
	last = ""
	for _, v := range c.Servers {
		if !v.valid() || v.Name <= last {
			return ErrCatalog
		}
		if _, ok := c.Account(v.Account); !ok {
			return ErrCatalog
		}
		last = v.Name
	}
	return nil
}

func knownVendor(id string) bool {
	_, ok := vps.Lookup(id)
	return ok
}

func managedVendor(id string) bool {
	_, ok := vps.LookupManaged(id)
	return ok
}

// VPS reads the account catalog (an empty one before the first write).
func (p Policy) VPS(s state.State) (VPSCatalog, error) {
	c := VPSCatalog{Schema: 1, Cluster: p.Cluster}
	raw, revision, err := readCheckpoint(s, VPSKey, p.Cluster, p.TrustRoot)
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

// Account returns the account named name.
func (c VPSCatalog) Account(name string) (VPSAccount, bool) {
	i := slices.IndexFunc(c.Accounts, func(a VPSAccount) bool { return a.Name == name })
	if i < 0 {
		return VPSAccount{}, false
	}
	return c.Accounts[i], true
}

// VPSAllowed: VPS accounts are system administration.
func (p Policy) VPSAllowed(s state.State, session access.Session, at int64, action string) error {
	return p.CertificateAllowed(s, session, at, action)
}

func (p Policy) VPSPage(s state.State, session access.Session, at int64, _ VPSQuery) (VPSPage, error) {
	if p.VPSAllowed(s, session, at, "vps") != nil {
		return VPSPage{}, access.ErrDenied
	}
	c, err := p.VPS(s)
	if err != nil {
		return VPSPage{}, err
	}
	out := VPSPage{Revision: c.Revision, Accounts: []VPSPublicAccount{}}
	// Owned-vendor accounts belong to OwnedVPSPage only (never shown with
	// managed ones, Jay 2026-11-28 14:04 KST).
	for _, a := range c.Accounts {
		if managedVendor(a.Vendor) {
			out.Accounts = append(out.Accounts, a.Public())
		}
	}
	out.Servers = append([]VPSServer{}, c.Servers...)
	return out, nil
}

func (p Policy) reduceVPS(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	if cmd.Key == VPSKey && cmd.Kind == state.ModuleReport {
		return p.reduceVPSReport(s, cmd)
	}
	if cmd.Key != VPSKey || cmd.Kind != state.Module {
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
	c, err := p.VPS(s)
	if err != nil {
		return nil, state.Invalid
	}
	if op.Change.Expected != c.Revision {
		return nil, state.ConditionFailed
	}
	switch op.Change.Action {
	case "put-vps-account":
		var q VPSAccountPut
		if canonical(op.Change.Payload, &q) != nil || !vps.ValidAccountName(q.Name) || !knownVendor(q.Vendor) || q.OverageKRWPerGB < 0 || q.OverageKRWPerGB > MaxOverageKRWPerGB || !q.Guard.valid() {
			return nil, state.Invalid
		}
		// An Owned vendor bills a fixed subscription with no overage, and its
		// traffic is protected per server, not by the account guard.
		if ownedVendor(q.Vendor) && (q.OverageKRWPerGB != 0 || q.Guard != (VPSGuard{}) || q.SSHKeyID != "") {
			return nil, state.Invalid
		}
		old, exists := c.Account(q.Name)
		if exists && old.Vendor != q.Vendor {
			return nil, state.ConditionFailed
		}
		a := old
		if !exists {
			if q.Credential == nil || len(c.Accounts) >= maxVPSAccounts {
				return nil, state.ConditionFailed
			}
			a = VPSAccount{Name: q.Name, Vendor: q.Vendor, AddedBy: op.Session.User, AddedAt: op.At}
		}
		if q.Credential != nil {
			cred := *q.Credential
			if cred.Validate() != nil || cred.Cluster != p.Cluster || cred.Account != q.Name || cred.Request != op.RequestID {
				return nil, state.Invalid
			}
			// Only a current voter can derive the key, so only one may seal.
			members, err := p.Members(s)
			if err != nil || !members.VoterKey(cred.Sealer) {
				return nil, state.Forbidden
			}
			if q.SSHKeyID != "" {
				return nil, state.Invalid // a new SSH key is not registered yet
			}
			a.Credential, a.SSHKeyID = cred, ""
		} else {
			if q.SSHKeyID != "" && (!vpsVendorID.MatchString(q.SSHKeyID) || a.Credential.SSHPublic == "") {
				return nil, state.Invalid
			}
			a.SSHKeyID = q.SSHKeyID
		}
		a.OverageKRWPerGB, a.Guard, a.UpdatedBy, a.UpdatedAt = q.OverageKRWPerGB, q.Guard, op.Session.User, op.At
		if a.UpdatedAt < a.AddedAt {
			return nil, state.Invalid
		}
		c.Accounts = slices.DeleteFunc(c.Accounts, func(x VPSAccount) bool { return x.Name == q.Name })
		c.Accounts = append(c.Accounts, a)
		slices.SortFunc(c.Accounts, func(x, y VPSAccount) int { return strings.Compare(x.Name, y.Name) })
	case "remove-vps-account":
		var q VPSAccountSelection
		if canonical(op.Change.Payload, &q) != nil || !vps.ValidAccountName(q.Name) {
			return nil, state.Invalid
		}
		if _, exists := c.Account(q.Name); !exists || slices.ContainsFunc(c.Servers, func(v VPSServer) bool { return v.Account == q.Name }) {
			return nil, state.ConditionFailed
		}
		owned, err := p.OwnedVPS(s)
		if err != nil {
			return nil, state.Invalid
		}
		if slices.ContainsFunc(owned.Servers, func(v OwnedVPS) bool { return v.Account == q.Name }) {
			return nil, state.ConditionFailed
		}
		c.Accounts = slices.DeleteFunc(c.Accounts, func(x VPSAccount) bool { return x.Name == q.Name })
	case "delete-vps-node":
		var q VPSServerSelection
		if canonical(op.Change.Payload, &q) != nil || !lifecycle.ValidID(q.Name) {
			return nil, state.Invalid
		}
		i := slices.IndexFunc(c.Servers, func(v VPSServer) bool { return v.Name == q.Name })
		if i < 0 || c.Servers[i].Phase == VPSDeleting {
			return nil, state.ConditionFailed
		}
		members, err := p.Members(s)
		if err != nil {
			return nil, state.Invalid
		}
		// A server that joined leaves through 'sfcli node drain' and
		// 'sfcli node remove' first; one that never joined goes at once.
		if e, ok := members.Entry(q.Name); ok && e.Phase != membership.Invited && !members.Gone(q.Name) {
			return nil, state.ConditionFailed
		}
		c.Servers[i].Phase, c.Servers[i].PhaseAt, c.Servers[i].DeleteRequest = VPSDeleting, max(op.At, c.Servers[i].PhaseAt), op.RequestID
	case "stop-vps-node":
		var q VPSServerStop
		if canonical(op.Change.Payload, &q) != nil || !lifecycle.ValidID(q.Name) || q.DNSWaitSeconds < 0 || q.DNSWaitSeconds > MaxVPSDNSWait {
			return nil, state.Invalid
		}
		i := slices.IndexFunc(c.Servers, func(v VPSServer) bool { return v.Name == q.Name })
		if i < 0 || c.Servers[i].Phase != VPSRunning {
			return nil, state.ConditionFailed
		}
		if code := p.vpsStoppable(s, q.Name); code != state.Applied {
			return nil, code
		}
		v := &c.Servers[i]
		v.Phase, v.PhaseAt, v.PowerRequest = VPSStopping, max(op.At, v.PhaseAt), op.RequestID
		v.StopAfter = v.PhaseAt + q.DNSWaitSeconds
	case "start-vps-node":
		var q VPSServerSelection
		if canonical(op.Change.Payload, &q) != nil || !lifecycle.ValidID(q.Name) {
			return nil, state.Invalid
		}
		i := slices.IndexFunc(c.Servers, func(v VPSServer) bool { return v.Name == q.Name })
		if i < 0 || c.Servers[i].Phase != VPSStopped && c.Servers[i].Phase != VPSCapped {
			return nil, state.ConditionFailed
		}
		v := &c.Servers[i]
		// A server stopped for its cap needs a higher cap (or a new month).
		if v.Phase == VPSCapped && !v.CapStop.Cleared(op.At, v.CapKRW) {
			return nil, state.ConditionFailed
		}
		v.Phase, v.PhaseAt, v.PowerRequest = VPSStarting, max(op.At, v.PhaseAt), op.RequestID
	case "set-vps-node-cap":
		var q VPSServerCap
		if canonical(op.Change.Payload, &q) != nil || !lifecycle.ValidID(q.Name) || q.CapKRW <= 0 || q.CapKRW > MaxVPSCapKRW {
			return nil, state.Invalid
		}
		i := slices.IndexFunc(c.Servers, func(v VPSServer) bool { return v.Name == q.Name })
		if i < 0 || c.Servers[i].Phase == VPSDeleting {
			return nil, state.ConditionFailed
		}
		if !validVPSCapAction(q.CapAction) {
			return nil, state.Invalid
		}
		c.Servers[i].CapKRW, c.Servers[i].CapAction = q.CapKRW, q.CapAction
	case "create-vps-node":
		var q VPSServerCreate
		if canonical(op.Change.Payload, &q) != nil || !q.valid() {
			return nil, state.Invalid
		}
		members, err := p.Members(s)
		if err != nil {
			return nil, state.Invalid
		}
		account, ok := c.Account(q.Account)
		// Only a Managed vendor's account may create servers here; an
		// Owned vendor's instances are attached, never bought (Jay
		// 2026-11-28 14:02 KST).
		if !ok || len(c.Servers) >= maxVPSServers || !managedVendor(account.Vendor) {
			return nil, state.ConditionFailed
		}
		if owned, err := p.OwnedVPS(s); err != nil {
			return nil, state.Invalid
		} else if _, taken := owned.Server(q.Name); taken {
			return nil, state.ConditionFailed
		}
		// Without a user script the leader installs over SSH with the
		// account key, so the vendor must put that key on the server.
		if q.Script == "" && (account.SSHKeyID == "" || !slices.Contains(q.SSHKeys, account.SSHKeyID)) {
			return nil, state.ConditionFailed
		}
		// An SSH install trusts the new host key on first contact, so
		// whoever answered could be promoted: SSH servers never vote.
		if q.Script == "" && q.Voter {
			return nil, state.Invalid
		}
		if _, taken := members.Entry(q.Name); taken || q.Name == p.Genesis.ID {
			return nil, state.ConditionFailed
		}
		if _, taken := c.Server(q.Name); taken {
			return nil, state.ConditionFailed
		}
		c.Servers = append(c.Servers, VPSServer{Name: q.Name, Account: q.Account, Zone: q.Zone, Image: q.Image, Flavor: q.Flavor, Script: q.Script, SSHKeys: q.SSHKeys,
			CapKRW: q.CapKRW, CapAction: q.CapAction, Voter: q.Voter, Port: q.Port, Request: op.RequestID, CreatedBy: op.Session.User, CreatedAt: op.At, Phase: VPSCreating, PhaseAt: op.At})
		slices.SortFunc(c.Servers, func(x, y VPSServer) int { return strings.Compare(x.Name, y.Name) })
	default:
		return nil, state.Invalid
	}
	return p.writeVPS(s, c)
}

// VPS server phases (devel/design/vps-nodes.md §3). Later steps add the
// stopping and stopped phases.
const (
	VPSCreating   = "creating"   // the leader is creating the instance
	VPSInstalling = "installing" // the instance runs; sfcd is being installed
	VPSRunning    = "running"    // the server joined the cluster
	VPSFailed     = "failed"
	VPSDeleting   = "deleting" // the leader is deleting the instance
	VPSStopping   = "stopping" // DNS is taken off; the leader shuts the instance down after StopAfter
	VPSStopped    = "stopped"  // powered off; the server stays a cordoned member
	VPSStarting   = "starting" // the leader powers the instance on
	// VPSCapped is a phase (powered off for the monthly cap) and the
	// vps-report action that starts that stop (running -> stopping).
	VPSCapped = "capped"
	// VPSStarted is a vps-report action: the stopped instance runs again
	// (starting -> running).
	VPSStarted = "started"
	// VPSDeleted is a vps-report action: the instance is gone, so the
	// record is removed.
	VPSDeleted = "deleted"
	// VPSCreateSent is a vps-report action, not a phase: the leader is
	// about to send the one Create this server gets.
	VPSCreateSent = "create-sent"
	// VPSInvited is a vps-report action: the leader signed the invitation
	// of the key the server enrolled with.
	VPSInvited = "invited"
)

const maxVPSServers = 64

// MaxVPSCapKRW bounds a server's monthly cap.
const MaxVPSCapKRW = 100_000_000

// VPSServer is one VPS server the cluster created or is creating. Its
// member entry (once enrolled) has the same ID as Name.
type VPSServer struct {
	Name, Account, Zone, Image, Flavor string
	Script                             string   `json:",omitempty"`
	SSHKeys                            []string `json:",omitempty"`
	CapKRW                             int64
	// CapAction is what the leader does over the cap: "" stops the
	// server (no drain), "notify" only shows it.
	CapAction string `json:",omitempty"`
	Voter     bool   // promote after joining (a separate signed promote-node)
	Port      uint16
	Request   string // the create-vps-node operation ID
	CreatedBy string
	CreatedAt int64
	Phase     string
	PhaseAt   int64
	// CreateSentAt is when the leader committed that it sends the Create
	// (0 = not yet). It is set once, before the Create, so no later leader
	// creates again.
	CreateSentAt int64 `json:",omitempty"`
	// Build is the leader's sfcd the new server must install, recorded
	// with installing; enrollment serves only that exact binary.
	Build *VPSBuild `json:",omitempty"`
	// PowerRequest is the last stop-vps-node or start-vps-node operation
	// ID; StopAfter is when the leader may shut the instance down (the
	// DNS wait after stop-vps-node).
	PowerRequest string `json:",omitempty"`
	StopAfter    int64  `json:",omitempty"`
	// CapStop is the last stop for the monthly cap (kept as the record).
	CapStop *VPSCapStop `json:",omitempty"`
	// DeleteRequest is the delete-vps-node operation ID (deleting only).
	DeleteRequest string `json:",omitempty"`
	// Invitation is the voter-signed join invitation for the enrolled key.
	// It is not secret: joining needs the key's private half.
	Invitation *membership.Invitation `json:",omitempty"`
	InstanceID string                 `json:",omitempty"`
	PublicIP   string                 `json:",omitempty"`
	Failure    string                 `json:",omitempty"`
}

// VPSBuild names one sfcd binary.
type VPSBuild struct {
	OS, Arch string
	SHA256   [32]byte
}

func (b VPSBuild) valid() bool {
	return b.OS == "linux" && (b.Arch == "amd64" || b.Arch == "arm64") && b.SHA256 != ([32]byte{})
}

// JoinID is the membership join ID of the server's invitation.
func (v VPSServer) JoinID() string {
	sum := sha256.Sum256([]byte("sfc-vps-join\x00" + v.Request))
	return "vps-" + hex.EncodeToString(sum[:12])
}

// Endpoint is the SFCP endpoint the server joins with.
func (v VPSServer) Endpoint() string {
	a, err := netip.ParseAddr(v.PublicIP)
	if err != nil {
		return ""
	}
	return netip.AddrPortFrom(a, v.Port).String()
}

// vpsStoppable reports whether member name may be powered off: a cordoned
// full member whose latest drain finished with every task moved, and, for
// a voter, one whose absence still leaves the cluster a failure to spare.
func (p Policy) vpsStoppable(s state.State, name string) state.Code {
	d, err := p.Members(s)
	if err != nil {
		return state.Invalid
	}
	e, ok := d.Entry(name)
	if !ok || !membership.FullMember(e) || d.Gone(name) || !d.Cordon(name).Enabled {
		return state.ConditionFailed
	}
	apps, err := p.Apps(s)
	if err != nil {
		return state.Invalid
	}
	drained := false
	for i := len(d.Drains) - 1; i >= 0; i-- {
		if d.Drains[i].Node != name {
			continue
		}
		status, err := p.nodeDrainStatus(s, apps, d.Drains[i])
		drained = err == nil && status.State == "Succeeded"
		break
	}
	if !drained {
		return state.ConditionFailed
	}
	return p.vpsVoterSpare(s, name)
}

// vpsVoterSpare reports whether member name may be powered off as far as
// the quorum goes (VPSVoterSpare).
func (p Policy) vpsVoterSpare(s state.State, name string) state.Code {
	d, err := p.Members(s)
	if err != nil {
		return state.Invalid
	}
	if !VPSVoterSpare(d, name) {
		return state.ConditionFailed
	}
	return state.Applied
}

// VPSVoterSpare is the quorum rule for powering a VPS server off: a
// non-voter always, a voter only if the rest of the voters still survive
// one more failure. An unknown member is false. The leader's cost watch
// uses it too, so it does not send a cap stop it knows is refused.
func VPSVoterSpare(d membership.Directory, name string) bool {
	e, ok := d.Entry(name)
	if !ok {
		return false
	}
	if !e.Peer.Voter {
		return true
	}
	voters := 0
	for _, other := range d.Entries {
		if other.Peer.Voter && membership.FullMember(other) && !d.Gone(other.Peer.ID) {
			voters++
		}
	}
	return voters-1 >= voters/2+2
}

// vpsJoinAllowed refuses a join dispatch for a VPS invitation whose server
// is no longer installing (for example being deleted).
func (p Policy) vpsJoinAllowed(s state.State, e membership.Entry) bool {
	if e.Phase == membership.Invited && strings.HasPrefix(e.JoinID, "owned-") {
		return p.ownedJoinAllowed(s, e)
	}
	if e.Phase != membership.Invited || !strings.HasPrefix(e.JoinID, "vps-") {
		return true
	}
	c, err := p.VPS(s)
	if err != nil {
		return false
	}
	v, ok := c.Server(e.Peer.ID)
	return ok && v.Phase == VPSInstalling && v.JoinID() == e.JoinID
}

// vpsEnrollServer checks a vps-enroll report against the server record:
// installing, not invited yet, from the server's own public address, for
// its own endpoint.
func (p Policy) vpsEnrollServer(s state.State, r MemberReport) (VPSServer, error) {
	c, err := p.VPS(s)
	if err != nil {
		return VPSServer{}, err
	}
	v, ok := c.Server(r.Node)
	if !ok || v.Phase != VPSInstalling || v.Invitation != nil || v.Build == nil || r.Source == "" || r.Source != v.PublicIP || r.Peer.Endpoint != v.Endpoint() {
		return VPSServer{}, ErrCatalog
	}
	return v, nil
}

// vpsEnrollJoinID is the join ID a vps-enroll report invites with: the
// managed server's, or else the owned server's.
func (p Policy) vpsEnrollJoinID(s state.State, r MemberReport) (string, error) {
	if v, err := p.vpsEnrollServer(s, r); err == nil {
		return v.JoinID(), nil
	}
	v, err := p.ownedEnrollServer(s, r)
	if err != nil {
		return "", err
	}
	return v.JoinID(), nil
}

// Tag is the description the instance is created with, so that a new
// leader finds an instance whose creation result it never saw.
func (v VPSServer) Tag(cluster [32]byte) string {
	return "sfc:" + hex.EncodeToString(cluster[:4]) + ":" + v.Request
}

// VPSServerCreate is create-vps-node's payload.
type VPSServerCreate struct {
	Name, Account, Zone, Image, Flavor string
	Script                             string   `json:",omitempty"`
	SSHKeys                            []string `json:",omitempty"`
	CapKRW                             int64
	CapAction                          string `json:",omitempty"`
	Voter                              bool
	Port                               uint16
}

var vpsVendorID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
var vpsFailure = regexp.MustCompile(`^[A-Z][A-Z_]{0,31}$`)

// Valid reports whether q is a well-formed create-vps-node payload.
func (q VPSServerCreate) Valid() bool { return q.valid() }

func (q VPSServerCreate) valid() bool {
	if !lifecycle.ValidID(q.Name) || q.Name == "genesis" || !vps.ValidAccountName(q.Account) || !vpsVendorID.MatchString(q.Zone) || !vpsVendorID.MatchString(q.Image) || !vpsVendorID.MatchString(q.Flavor) ||
		q.Script != "" && !vpsVendorID.MatchString(q.Script) || len(q.SSHKeys) > 4 || q.CapKRW <= 0 || q.CapKRW > MaxVPSCapKRW || !validVPSCapAction(q.CapAction) || q.Port == 0 {
		return false
	}
	last := ""
	for _, k := range q.SSHKeys {
		if !vpsVendorID.MatchString(k) || k <= last {
			return false
		}
		last = k
	}
	return true
}

func (v VPSServer) valid() bool {
	q := VPSServerCreate{Name: v.Name, Account: v.Account, Zone: v.Zone, Image: v.Image, Flavor: v.Flavor, Script: v.Script, SSHKeys: v.SSHKeys, CapKRW: v.CapKRW, CapAction: v.CapAction, Voter: v.Voter, Port: v.Port}
	if !q.valid() || v.Request == "" || len(v.Request) > 128 || !validVPSUser(v.CreatedBy) || v.CreatedAt <= 0 || v.PhaseAt < v.CreatedAt || v.CreateSentAt != 0 && v.CreateSentAt < v.CreatedAt {
		return false
	}
	if v.CapStop != nil && !v.CapStop.valid() || v.Phase == VPSCapped && v.CapStop == nil {
		return false
	}
	switch v.Phase {
	case VPSCreating:
		return v.InstanceID == "" && v.PublicIP == "" && v.Failure == "" && v.DeleteRequest == ""
	case VPSInstalling:
		return validVPSInstance(v.InstanceID, v.PublicIP) && v.Failure == "" && v.DeleteRequest == ""
	case VPSRunning:
		return validVPSInstance(v.InstanceID, v.PublicIP) && v.Failure == "" && v.Invitation != nil && v.DeleteRequest == "" && len(v.PowerRequest) <= 128
	case VPSStopping, VPSStopped, VPSStarting, VPSCapped:
		return validVPSInstance(v.InstanceID, v.PublicIP) && v.Failure == "" && v.Invitation != nil && v.DeleteRequest == "" && v.PowerRequest != "" && len(v.PowerRequest) <= 128 && v.StopAfter >= v.CreatedAt
	case VPSDeleting:
		return v.DeleteRequest != "" && len(v.DeleteRequest) <= 128 && (v.InstanceID == "" || vpsVendorID.MatchString(v.InstanceID)) && (v.PublicIP == "" || validVPSAddress(v.PublicIP)) && (v.Failure == "" || vpsFailure.MatchString(v.Failure))
	case VPSFailed:
		return vpsFailure.MatchString(v.Failure) && v.DeleteRequest == "" && (v.InstanceID == "" || vpsVendorID.MatchString(v.InstanceID)) && (v.PublicIP == "" || validVPSAddress(v.PublicIP))
	}
	return false
}

// validVPSAddress is a public IPv4 address: the leader reaches a new VPS
// over the internet, never over a private range.
func validVPSAddress(ip string) bool {
	a, err := netip.ParseAddr(ip)
	return err == nil && a.Is4() && a.String() == ip && a.IsGlobalUnicast() && !a.IsPrivate()
}

func validVPSInstance(id, ip string) bool { return vpsVendorID.MatchString(id) && validVPSAddress(ip) }

// Server returns the VPS server named name.
func (c VPSCatalog) Server(name string) (VPSServer, bool) {
	i := slices.IndexFunc(c.Servers, func(v VPSServer) bool { return v.Name == name })
	if i < 0 {
		return VPSServer{}, false
	}
	return c.Servers[i], true
}

// VPSReport is the leader's record of a provider effect on one server: the
// instance runs at an address (installing) or creation failed.
type VPSReport struct {
	Schema              uint8
	Cluster, Reporter   [32]byte
	Server, Action      string
	InstanceID          string                 `json:",omitempty"`
	PublicIP            string                 `json:",omitempty"`
	Failure             string                 `json:",omitempty"`
	Build               *VPSBuild              `json:",omitempty"` // installing
	Invitation          *membership.Invitation `json:",omitempty"` // invited
	Cap                 *VPSCapStop            `json:",omitempty"` // capped
	RootRevision, Epoch uint64
	At                  uint64
	Signature           []byte
}

func VPSReportBytes(r VPSReport) []byte {
	r.Signature = nil
	raw, _ := json.Marshal(r)
	return append([]byte("sfc-vps-report-1\x00"), raw...)
}

func (r VPSReport) Command() (state.Command, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return state.Command{}, err
	}
	cmd := state.Command{Kind: state.ModuleReport, Actor: "node/" + hex.EncodeToString(r.Reporter[:]), Epoch: r.Epoch, Key: VPSKey, Expected: r.RootRevision, Value: string(raw)}
	cmd.RequestID = state.ReportRequestID(cmd)
	_, err = state.EncodeCommand(cmd)
	return cmd, err
}

func (p Policy) vpsReport(s state.State, cmd state.Command) (VPSReport, error) {
	var r VPSReport
	if cmd.Key != VPSKey || cmd.Kind != state.ModuleReport || canonical([]byte(cmd.Value), &r) != nil || r.Schema != 1 || r.Cluster != p.Cluster || r.Epoch != s.ModuleEpoch() || r.RootRevision != s.Object(VPSKey).Revision || r.At == 0 || r.At > math.MaxInt64 || !ed25519.Verify(r.Reporter[:], VPSReportBytes(r), r.Signature) {
		return r, ErrCatalog
	}
	want, err := r.Command()
	current, pe := p.Current(s)
	if err != nil || want != cmd || pe != nil || !current.Issuer(r.Reporter).Enabled {
		return r, ErrCatalog
	}
	// Only a voter can open the provider key, so only a voter drives VPSes.
	if members, err := p.Members(s); err != nil || !members.VoterKey(r.Reporter) {
		return r, ErrCatalog
	}
	if r.Action != VPSInstalling && r.Build != nil || r.Action != VPSInvited && r.Invitation != nil || r.Action != VPSCapped && r.Cap != nil {
		return r, ErrCatalog
	}
	switch r.Action {
	case VPSCreateSent, VPSRunning, VPSDeleted, VPSStopped, VPSStarted:
		if r.InstanceID != "" || r.PublicIP != "" || r.Failure != "" {
			return r, ErrCatalog
		}
	case VPSCapped:
		if r.Cap == nil || !r.Cap.valid() || r.Cap.At != int64(r.At) || r.Cap.Month != vps.MonthOf(time.Unix(r.Cap.At, 0)) || r.InstanceID != "" || r.PublicIP != "" || r.Failure != "" {
			return r, ErrCatalog
		}
	case VPSInvited:
		if r.Invitation == nil || r.Invitation.Verify(p.Cluster, r.Reporter) != nil || r.InstanceID != "" || r.PublicIP != "" || r.Failure != "" {
			return r, ErrCatalog
		}
	case VPSInstalling:
		if !validVPSInstance(r.InstanceID, r.PublicIP) || r.Failure != "" || r.Build == nil || !r.Build.valid() {
			return r, ErrCatalog
		}
	case VPSFailed:
		if !vpsFailure.MatchString(r.Failure) || r.InstanceID != "" && !vpsVendorID.MatchString(r.InstanceID) || r.PublicIP != "" {
			return r, ErrCatalog
		}
	default:
		return r, ErrCatalog
	}
	return r, nil
}

// ResolveVPSReport admits a leader's vps-report from caller.
func (p Policy) ResolveVPSReport(s state.State, caller [32]byte, raw []byte) (state.Command, error) {
	var r VPSReport
	if canonical(raw, &r) != nil || r.Reporter != caller {
		return state.Command{}, ErrCatalog
	}
	cmd, err := r.Command()
	if err == nil {
		_, err = p.vpsReport(s, cmd)
	}
	return cmd, err
}

func (p Policy) reduceVPSReport(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	r, err := p.vpsReport(s, cmd)
	if err != nil {
		return nil, state.Forbidden
	}
	c, err := p.VPS(s)
	if err != nil {
		return nil, state.Invalid
	}
	i := slices.IndexFunc(c.Servers, func(v VPSServer) bool { return v.Name == r.Server })
	want := VPSCreating
	switch r.Action {
	case VPSInvited, VPSRunning:
		want = VPSInstalling
	case VPSCapped:
		want = VPSRunning
	case VPSDeleted:
		want = VPSDeleting
	case VPSStopped:
		want = VPSStopping
	case VPSStarted:
		want = VPSStarting
	}
	if i < 0 || c.Servers[i].Phase != want || r.Action == VPSInvited && c.Servers[i].Invitation != nil || r.Action == VPSRunning && c.Servers[i].Invitation == nil {
		return nil, state.ConditionFailed
	}
	v := c.Servers[i]
	at := max(int64(r.At), v.CreatedAt)
	switch r.Action {
	case VPSCreateSent:
		if v.CreateSentAt != 0 {
			return nil, state.ConditionFailed
		}
		v.CreateSentAt = at
	case VPSInvited:
		members, err := p.Members(s)
		if err != nil {
			return nil, state.Invalid
		}
		e, ok := members.Entry(v.Name)
		if !ok || e.Phase != membership.Invited || e.JoinID != v.JoinID() || e.Peer != r.Invitation.Target || e.Peer.Endpoint != v.Endpoint() || r.Invitation.JoinID != e.JoinID {
			return nil, state.ConditionFailed
		}
		v.Invitation = r.Invitation
	case VPSRunning:
		// The invited key joined and is a full member now.
		members, err := p.Members(s)
		if err != nil {
			return nil, state.Invalid
		}
		e, ok := members.Entry(v.Name)
		if !ok || !membership.FullMember(e) || e.JoinID != v.JoinID() || e.CurrentPeer().Key != v.Invitation.Target.Key || members.Gone(v.Name) {
			return nil, state.ConditionFailed
		}
		v.Phase, v.PhaseAt = VPSRunning, max(at, v.PhaseAt)
	case VPSDeleted:
		c.Servers = slices.Delete(c.Servers, i, i+1)
		return p.writeVPS(s, c)
	case VPSCapped:
		// The cap the leader judged against must be the cap now, and a
		// voter may go only with a failure to spare.
		if r.Cap.CapKRW != v.CapKRW || at != r.Cap.At || v.CapAction != VPSCapStopAction {
			return nil, state.ConditionFailed
		}
		if code := p.vpsVoterSpare(s, v.Name); code != state.Applied {
			return nil, code
		}
		stop := *r.Cap
		v.Phase, v.PhaseAt, v.CapStop, v.PowerRequest = VPSStopping, max(at, v.PhaseAt), &stop, stop.request()
		v.StopAfter = v.PhaseAt + VPSCapDNSWait
	case VPSStopped:
		if at < v.StopAfter {
			return nil, state.ConditionFailed // DNS wait not over
		}
		v.Phase, v.PhaseAt = VPSStopped, max(at, v.PhaseAt)
		if v.CapStop != nil && v.PowerRequest == v.CapStop.request() {
			v.Phase = VPSCapped
		}
	case VPSStarted:
		v.Phase, v.PhaseAt = VPSRunning, max(at, v.PhaseAt)
	default:
		v.Phase, v.PhaseAt, v.InstanceID, v.PublicIP, v.Failure, v.Build = r.Action, at, r.InstanceID, r.PublicIP, r.Failure, r.Build
	}
	c.Servers[i] = v
	return p.writeVPS(s, c)
}

func (p Policy) writeVPS(s state.State, c VPSCatalog) (map[string][]byte, state.Code) {
	c.Revision++
	if c.validate(p.Cluster) != nil {
		return nil, state.Invalid
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, state.Invalid
	}
	return writeCheckpoint(s, VPSKey, p.Cluster, p.TrustRoot, c.Revision, raw)
}

// vpsBook is the VPSKey Raft book (see book.go).
var vpsBook = Book{
	Key:     VPSKey,
	Actions: []string{"put-vps-account", "remove-vps-account", "create-vps-node", "delete-vps-node", "stop-vps-node", "start-vps-node", "set-vps-node-cap"},
	Reduce:  Policy.reduceVPS,
	AdmitReport: func(p Policy, s state.State, cmd state.Command) error {
		_, err := p.vpsReport(s, cmd)
		return err
	},
	ReportOnly: true,
}
