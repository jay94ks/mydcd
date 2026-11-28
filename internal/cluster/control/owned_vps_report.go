// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"net/netip"
	"slices"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/cluster/state"
)

// Owned VPS report actions: what the leader found while installing an
// attached owned VPS. Each is one committed step, so a new leader carries
// on from the record (devel/design/vps-hostinger.md §3).
const (
	// OwnedChecked: the vendor shows the instance running at PublicIP. An
	// ssh or manual install waits for enrollment from that address next;
	// an existing server whose member endpoint is that address is running.
	OwnedChecked = "checked"
	// OwnedInvited: the enrolled key got its voter-signed invitation.
	OwnedInvited = "invited"
	// OwnedJoined: the invited key joined; the server is running.
	OwnedJoined = "joined"
	// OwnedFailedReport: the install stopped with a failure code.
	OwnedFailedReport = "failed"
	// OwnedLimiting: hold user traffic off the server before its monthly
	// bandwidth runs out. Committed before DNS or backends change.
	OwnedLimiting = "limiting"
	// OwnedRestoredReport: the vendor's month reset; end the hold.
	OwnedRestoredReport = "restored"
	// OwnedExpired: the subscription ended and the vendor removed the VM.
	OwnedExpired = "expired"
)

// OwnedVPSReport is the leader's signed owned-vps-report.
type OwnedVPSReport struct {
	Schema              uint8
	Cluster, Reporter   [32]byte
	Server, Action      string
	PublicIP            string                 `json:",omitempty"` // checked
	Build               *VPSBuild              `json:",omitempty"` // checked (ssh, manual)
	Invitation          *membership.Invitation `json:",omitempty"` // invited
	Failure             string                 `json:",omitempty"` // failed
	Limit               *OwnedLimit            `json:",omitempty"` // limiting
	RootRevision, Epoch uint64
	At                  uint64
	Signature           []byte
}

func OwnedVPSReportBytes(r OwnedVPSReport) []byte {
	r.Signature = nil
	raw, _ := json.Marshal(r)
	return append([]byte("sfc-owned-vps-report-1\x00"), raw...)
}

func (r OwnedVPSReport) Command() (state.Command, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return state.Command{}, err
	}
	cmd := state.Command{Kind: state.ModuleReport, Actor: "node/" + hex.EncodeToString(r.Reporter[:]), Epoch: r.Epoch, Key: OwnedVPSKey, Expected: r.RootRevision, Value: string(raw)}
	cmd.RequestID = state.ReportRequestID(cmd)
	_, err = state.EncodeCommand(cmd)
	return cmd, err
}

// JoinID is the membership join ID of the server's invitation.
func (v OwnedVPS) JoinID() string {
	sum := sha256.Sum256([]byte("sfc-owned-vps-join\x00" + v.Request))
	return "owned-" + hex.EncodeToString(sum[:12])
}

// Endpoint is the SFCP endpoint a new server joins with.
func (v OwnedVPS) Endpoint() string {
	a, err := netip.ParseAddr(v.PublicIP)
	if err != nil || v.Port == 0 {
		return ""
	}
	return netip.AddrPortFrom(a, v.Port).String()
}

func (p Policy) ownedVPSReport(s state.State, cmd state.Command) (OwnedVPSReport, error) {
	var r OwnedVPSReport
	if cmd.Key != OwnedVPSKey || cmd.Kind != state.ModuleReport || canonical([]byte(cmd.Value), &r) != nil || r.Schema != 1 || r.Cluster != p.Cluster || r.Epoch != s.ModuleEpoch() || r.RootRevision != s.Object(OwnedVPSKey).Revision || r.At == 0 || r.At > math.MaxInt64 || !ed25519.Verify(r.Reporter[:], OwnedVPSReportBytes(r), r.Signature) {
		return r, ErrCatalog
	}
	want, err := r.Command()
	current, pe := p.Current(s)
	if err != nil || want != cmd || pe != nil || !current.Issuer(r.Reporter).Enabled {
		return r, ErrCatalog
	}
	// Only a voter can open the provider token, so only a voter drives them.
	if members, err := p.Members(s); err != nil || !members.VoterKey(r.Reporter) {
		return r, ErrCatalog
	}
	if r.Action != OwnedChecked && (r.PublicIP != "" || r.Build != nil) || r.Action != OwnedInvited && r.Invitation != nil || r.Action != OwnedFailedReport && r.Failure != "" || r.Action != OwnedLimiting && r.Limit != nil {
		return r, ErrCatalog
	}
	switch r.Action {
	case OwnedChecked:
		if !validVPSAddress(r.PublicIP) || r.Build != nil && !r.Build.valid() {
			return r, ErrCatalog
		}
	case OwnedInvited:
		if r.Invitation == nil || r.Invitation.Verify(p.Cluster, r.Reporter) != nil {
			return r, ErrCatalog
		}
	case OwnedJoined, OwnedRestoredReport, OwnedExpired:
	case OwnedLimiting:
		if r.Limit == nil || !r.Limit.valid() || r.Limit.At != int64(r.At) {
			return r, ErrCatalog
		}
	case OwnedFailedReport:
		if !vpsFailure.MatchString(r.Failure) {
			return r, ErrCatalog
		}
	default:
		return r, ErrCatalog
	}
	return r, nil
}

// ResolveOwnedVPSReport admits a leader's owned-vps-report from caller.
func (p Policy) ResolveOwnedVPSReport(s state.State, caller [32]byte, raw []byte) (state.Command, error) {
	var r OwnedVPSReport
	if canonical(raw, &r) != nil || r.Reporter != caller {
		return state.Command{}, ErrCatalog
	}
	cmd, err := r.Command()
	if err == nil {
		_, err = p.ownedVPSReport(s, cmd)
	}
	return cmd, err
}

func (p Policy) reduceOwnedVPSReport(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	r, err := p.ownedVPSReport(s, cmd)
	if err != nil {
		return nil, state.Forbidden
	}
	c, err := p.OwnedVPS(s)
	if err != nil {
		return nil, state.Invalid
	}
	i := slices.IndexFunc(c.Servers, func(v OwnedVPS) bool { return v.Name == r.Server })
	if i < 0 {
		return nil, state.ConditionFailed
	}
	v := &c.Servers[i]
	switch r.Action {
	case OwnedLimiting, OwnedRestoredReport, OwnedExpired:
		if v.Phase != OwnedRunning {
			return nil, state.ConditionFailed
		}
		return p.reduceOwnedRunning(s, c, v, r)
	}
	if v.Phase != OwnedInstalling {
		return nil, state.ConditionFailed
	}
	members, err := p.Members(s)
	if err != nil {
		return nil, state.Invalid
	}
	at := max(int64(r.At), v.UpdatedAt)
	switch r.Action {
	case OwnedChecked:
		// Checked once; existing servers need no build, the others do.
		if v.PublicIP != "" || (r.Build == nil) != (v.Install == OwnedInstallExisting) {
			return nil, state.ConditionFailed
		}
		v.PublicIP, v.Build = r.PublicIP, r.Build
		if v.Install == OwnedInstallExisting {
			// sfcd already runs there: the member's endpoint must be the
			// instance's address, or this is some other server.
			e, ok := members.Entry(v.Name)
			if !ok || !membership.FullMember(e) || members.Gone(v.Name) || !sameHost(e.CurrentPeer().Endpoint, r.PublicIP) {
				return nil, state.ConditionFailed
			}
			v.Phase = OwnedRunning
		}
	case OwnedInvited:
		e, ok := members.Entry(v.Name)
		if v.Build == nil || v.Invitation != nil || !ok || e.Phase != membership.Invited || e.JoinID != v.JoinID() || e.Peer != r.Invitation.Target || e.Peer.Endpoint != v.Endpoint() || r.Invitation.JoinID != e.JoinID {
			return nil, state.ConditionFailed
		}
		v.Invitation = r.Invitation
	case OwnedJoined:
		e, ok := members.Entry(v.Name)
		if v.Invitation == nil || !ok || !membership.FullMember(e) || e.JoinID != v.JoinID() || e.CurrentPeer().Key != v.Invitation.Target.Key || members.Gone(v.Name) {
			return nil, state.ConditionFailed
		}
		v.Phase = OwnedRunning
	case OwnedFailedReport:
		v.Phase, v.Failure = OwnedFailed, r.Failure
	}
	v.UpdatedAt = at
	return p.writeOwnedVPS(s, c)
}

// reduceOwnedRunning applies a running server's traffic hold, its end, or
// the end of its subscription.
func (p Policy) reduceOwnedRunning(s state.State, c OwnedVPSCatalog, v *OwnedVPS, r OwnedVPSReport) (map[string][]byte, state.Code) {
	at := max(int64(r.At), v.UpdatedAt)
	switch r.Action {
	case OwnedLimiting:
		// One hold at a time, in the mode chosen now, and none in a month
		// an operator already ended one.
		if v.Limit != nil || r.Limit.Mode != v.Protect || v.Restored != nil && v.Restored.By != "" && v.Restored.Month == r.Limit.Month {
			return nil, state.ConditionFailed
		}
		l := *r.Limit
		v.Limit = &l
	case OwnedRestoredReport:
		// The leader ends a hold only once its month is over.
		month := OwnedMonthOf(time.Unix(int64(r.At), 0))
		if v.Limit == nil || v.Limit.Month >= month {
			return nil, state.ConditionFailed
		}
		v.Restored, v.Limit = &OwnedRestore{At: at, Month: month}, nil
	case OwnedExpired:
		v.Phase, v.Failure, v.Limit = OwnedFailed, "EXPIRED", nil
	}
	v.UpdatedAt = at
	return p.writeOwnedVPS(s, c)
}

func sameHost(endpoint, ip string) bool {
	ap, err := netip.ParseAddrPort(endpoint)
	want, werr := netip.ParseAddr(ip)
	return err == nil && werr == nil && ap.Addr().Unmap() == want.Unmap()
}

// ownedEnrollServer checks a vps-enroll report against an owned server:
// checked, not invited yet, from the instance's own address, for its own
// endpoint.
func (p Policy) ownedEnrollServer(s state.State, r MemberReport) (OwnedVPS, error) {
	c, err := p.OwnedVPS(s)
	if err != nil {
		return OwnedVPS{}, err
	}
	v, ok := c.Server(r.Node)
	if !ok || v.Phase != OwnedInstalling || v.Install == OwnedInstallExisting || v.Invitation != nil || v.Build == nil || r.Source == "" || r.Source != v.PublicIP || r.Peer.Endpoint != v.Endpoint() {
		return OwnedVPS{}, ErrCatalog
	}
	return v, nil
}

// ownedJoinAllowed refuses a join dispatch for an owned invitation whose
// server is no longer installing (detached or failed).
func (p Policy) ownedJoinAllowed(s state.State, e membership.Entry) bool {
	c, err := p.OwnedVPS(s)
	if err != nil {
		return false
	}
	v, ok := c.Server(e.Peer.ID)
	return ok && v.Phase == OwnedInstalling && v.JoinID() == e.JoinID
}

// OwnedVPSStatus is the leader's memory of the owned VPS servers it reads
// from the vendor (never in Raft): bandwidth this month and the
// subscription's remaining period.
type OwnedVPSStatus struct {
	Leader  string
	Servers []OwnedVPSServerStatus
}

// OwnedVPSServerStatus is one running owned VPS as last read.
type OwnedVPSServerStatus struct {
	Name      string
	UpdatedAt int64
	// UsedMB and MonthMB are this month's traffic and allowance (vendor
	// units); ReachAt is when the use reaches the allowance at the latest
	// rate (0 = not known yet, or no traffic).
	UsedMB, MonthMB, ReachAt int64
	// What the vendor reports for the VM: its plan, location and OS image,
	// and its power state (pending, active, working, off, error). "off"
	// while the record runs means the vendor or someone in its panel
	// stopped it.
	Plan           string `json:",omitempty"`
	Zone           string `json:",omitempty"`
	Image          string `json:",omitempty"`
	InstanceStatus string `json:",omitempty"`
	// The subscription: remaining period only; renewal stays in the
	// vendor's panel. RenewalCost is in Currency's minor units.
	SubscriptionStatus string `json:",omitempty"`
	ExpiresAt          int64  `json:",omitempty"`
	AutoRenew          bool   `json:",omitempty"`
	Currency           string `json:",omitempty"`
	RenewalCost        int64  `json:",omitempty"`
	Failure            string `json:",omitempty"`
	FailureAt          int64  `json:",omitempty"`
}
