// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"

	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
)

// MemberReport binds an adapter's positive observation or unresolved effect to
// the original shared A2 job. It grants no user or legacy management rights.
// Signers are crash-fault members, not an alternative voting/certificate quorum.
// Installation is the sole report an approved, not-yet-installed key can make.
type MemberReport struct {
	// Source is the client address a vps-enroll request came from, as the
	// reporting ingress saw it on the connection.
	Source          string                   `json:",omitempty"`
	DrainJob        string                   `json:",omitempty"`
	IdentityFailure string                   `json:",omitempty"`
	Identity        *lifecycle.IdentityProof `json:",omitempty"`
	Configuration   *lifecycle.Configuration `json:",omitempty"`
	// Recovery is the signed `sfcd recover` plan a "recovered" report installs.
	Recovery *lifecycle.Recovery `json:",omitempty"`
	// Restore is the signed `sfcd restore` record a "restored" report
	// applies. Only the restoring server's offline start applies it.
	Restore                             *lifecycle.ClusterRestore `json:",omitempty"`
	Proof                               *lifecycle.Proof          `json:",omitempty"`
	Operation                           string                    `json:",omitempty"`
	Schema                              uint8
	Cluster, Reporter                   [32]byte
	Action, Node                        string
	Expected, JobID, ConfigurationIndex uint64
	Peer                                config.Peer
	Ack                                 *membership.Ack `json:",omitempty"`
	Epoch                               uint64
	RequestID                           string
	RootRevision                        uint64
	Signature                           []byte
}

func MemberReportBytes(r MemberReport) []byte {
	r.Signature = nil
	b, _ := json.Marshal(r)
	return append([]byte("sfc-member-report-1\x00"), b...)
}
func (r MemberReport) Command() (state.Command, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return state.Command{}, err
	}
	cmd := state.Command{Kind: state.Module, Actor: "node/" + hex.EncodeToString(r.Reporter[:]), Epoch: r.Epoch, RequestID: r.RequestID, Key: MembersKey, Expected: r.RootRevision, Value: string(raw)}
	_, err = state.EncodeCommand(cmd)
	return cmd, err
}

// ResolveMemberReport keeps owner observations on the authenticated SFCP
// management lane. A retained exact receipt may be read after its CAS advances;
// it never gives that reporter permission to create a different report.
func (p Policy) ResolveMemberReport(s state.State, caller [32]byte, raw []byte) (state.Command, error) {
	var report MemberReport
	if canonical(raw, &report) != nil || report.Schema != 1 || report.Cluster != p.Cluster || report.Reporter != caller || !ed25519.Verify(ed25519.PublicKey(caller[:]), MemberReportBytes(report), report.Signature) {
		return state.Command{}, ErrCatalog
	}
	d, err := p.Members(s)
	if err != nil || !d.MemberKey(caller) || report.Action == "restored" {
		return state.Command{}, ErrCatalog
	}
	command, err := report.Command()
	if err != nil {
		return command, err
	}
	if _, found := s.LookupResult(command); found {
		return command, nil
	}
	_, err = p.memberReport(s, command)
	return command, err
}
func (p Policy) memberReport(s state.State, cmd state.Command) (MemberReport, error) {
	var r MemberReport
	if cmd.Kind != state.Module || cmd.Key != MembersKey || canonical([]byte(cmd.Value), &r) != nil || r.Schema != 1 || r.Cluster != p.Cluster || r.Reporter == ([32]byte{}) || r.Epoch != s.ModuleEpoch() || r.RequestID == "" || !lifecycle.ValidID(r.Node) || !ed25519.Verify(ed25519.PublicKey(r.Reporter[:]), MemberReportBytes(r), r.Signature) {
		return r, ErrCatalog
	}
	expected, err := r.Command()
	if err != nil || expected != cmd {
		return r, ErrCatalog
	}
	d, err := p.Members(s)
	if err != nil {
		return r, err
	}
	if r.Action != "recovered" && r.Recovery != nil || r.Action != "restored" && r.Restore != nil {
		return r, ErrCatalog
	}
	if r.Action != "configuration" && r.Action != "recovered" && r.Configuration != nil || r.Action != "node-proof" && r.Proof != nil || r.Action != "remove-dispatch" && r.Action != "remove-unknown" && r.Action != "identity-prepared" && r.Action != "identity-activate" && r.Action != "identity-installed" && r.Action != "identity-failed" && r.Action != "drain-move-start" && r.Operation != "" {
		return r, ErrCatalog
	}
	if r.DrainJob != "" && r.Action != "drain-move-start" {
		return r, ErrCatalog
	}
	if r.IdentityFailure != "" && r.Action != "identity-failed" {
		return r, ErrCatalog
	}
	if r.Identity != nil && r.Action != "identity-prepared" {
		return r, ErrCatalog
	}
	if r.Source != "" && r.Action != "vps-enroll" {
		return r, ErrCatalog
	}
	switch r.Action {
	case "drain-move-start":
		if !lifecycle.ValidID(r.DrainJob) || r.Expected != d.Revision || r.JobID != 0 || r.Peer != (config.Peer{}) || r.Ack != nil || r.ConfigurationIndex != 0 {
			return r, ErrCatalog
		}
		if _, _, err := p.drainMoveJob(d, r.Node, r.Operation, r.DrainJob); err != nil {
			return r, err
		}
	case "identity-prepared", "identity-activate", "identity-installed", "identity-failed":
		row, found := d.IdentityRotation(r.Node, r.Operation)
		entry, exists := d.Entry(r.Node)
		if !found || !exists || r.Expected != d.Revision || r.Reporter != mustCurrentPeer(entry) || r.JobID != 0 || r.Peer != (config.Peer{}) || r.Ack != nil || r.ConfigurationIndex != 0 {
			return r, ErrCatalog
		}
		if r.Action == "identity-prepared" && (row.Phase != "Preparing" || r.Identity == nil || r.Identity.Old != r.Reporter || r.Identity.Node != r.Node || r.Identity.Operation != r.Operation) || r.Action == "identity-activate" && row.Phase != "Prepared" || r.Action == "identity-installed" && (row.Phase != "Activated" || row.Proof == nil || row.Proof.New != r.Reporter) {
			return r, ErrCatalog
		}
	case "configuration":
		if r.Configuration == nil || r.Configuration.Validate() != nil || r.Proof != nil || r.Operation != "" || r.JobID != 0 || r.Peer != (config.Peer{}) || r.Ack != nil || r.ConfigurationIndex != 0 || r.Expected != d.Revision {
			return r, ErrCatalog
		}
		entry, found := d.Entry(r.Node)
		if !found || entry.CurrentPeer().Key != hex.EncodeToString(r.Reporter[:]) {
			return r, ErrCatalog
		}
	case "recovered":
		// The reporter is a surviving member; the plan carries the node root's
		// own signature. Topology.Recover checks the plan against the change.
		if r.Configuration == nil || r.Recovery == nil || r.Configuration.Validate() != nil || r.Proof != nil || r.Operation != "" || r.JobID != 0 || r.Peer != (config.Peer{}) || r.Ack != nil || r.ConfigurationIndex != 0 || r.Expected != d.Revision {
			return r, ErrCatalog
		}
		entry, found := d.Entry(r.Node)
		if !found || entry.CurrentPeer().Key != hex.EncodeToString(r.Reporter[:]) {
			return r, ErrCatalog
		}
	case "restored":
		// The reporter is the new server itself, not a member yet: its
		// authority is the backup it opened, and the record binds the exact
		// snapshot position, so this report fits only that one state.
		if r.Restore == nil || r.Configuration != nil || r.Proof != nil || r.Operation != "" || r.JobID != 0 || r.Ack != nil || r.ConfigurationIndex != 0 || r.Expected != d.Revision || r.Reporter != r.Restore.Key || r.Node != r.Restore.Node || r.Peer.ID != r.Node || !r.Peer.Voter || r.Restore.StateIndex != s.Index() || !r.Restore.Valid() || r.Restore.Cluster != p.Cluster {
			return r, ErrCatalog
		}
		return r, nil
	case "node-proof":
		if r.Proof == nil || r.Proof.Node != r.Node || r.Configuration != nil || r.Operation != "" || r.JobID != 0 || r.Peer != (config.Peer{}) || r.Ack != nil || r.ConfigurationIndex != 0 || r.Expected != d.Revision {
			return r, ErrCatalog
		}
	case "remove-dispatch", "remove-unknown":
		op, exists := d.NodeOperation(r.Operation)
		if !exists || op.Node != r.Node || r.Expected != d.Revision || r.JobID != 0 || r.Peer != (config.Peer{}) || r.Ack != nil || r.Action == "remove-dispatch" && r.ConfigurationIndex == 0 || r.Action == "remove-unknown" && r.ConfigurationIndex != 0 {
			return r, ErrCatalog
		}
	case "dispatch":
		if r.JobID == 0 || r.ConfigurationIndex == 0 || r.Peer != (config.Peer{}) || r.Ack != nil {
			return r, ErrCatalog
		}
	case "unknown":
		if r.JobID == 0 || r.ConfigurationIndex != 0 || r.Peer != (config.Peer{}) || r.Ack != nil {
			return r, ErrCatalog
		}
	case "absent":
		// Only a voter (the leader that read the committed configuration).
		if r.JobID == 0 || r.ConfigurationIndex == 0 || r.Peer != (config.Peer{}) || r.Ack != nil || !d.VoterKey(r.Reporter) {
			return r, ErrCatalog
		}
	case "join-aborted":
		if r.JobID != 0 || r.ConfigurationIndex == 0 || r.Peer != (config.Peer{}) || r.Ack != nil || !d.VoterKey(r.Reporter) {
			return r, ErrCatalog
		}
	case "observe":
		if r.JobID == 0 || r.ConfigurationIndex == 0 || r.Peer.ID != r.Node || r.Ack != nil {
			return r, ErrCatalog
		}
	case "vps-enroll":
		if r.Expected != d.Revision || r.JobID != 0 || r.ConfigurationIndex != 0 || r.Ack != nil || r.Peer.ID != r.Node || r.Peer.Voter || !d.MemberKey(r.Reporter) {
			return r, ErrCatalog
		}
		if _, err := p.vpsEnrollJoinID(s, r); err != nil {
			return r, err
		}
	case "installed":
		// A current installed control may relay the target's immutable signed
		// ACK. A provisional reporter can carry ONLY its own ACK below.
		if r.JobID != 0 || r.ConfigurationIndex != 0 || r.Peer != (config.Peer{}) || r.Ack == nil || r.Ack.Node != r.Node || r.Ack.Key != r.Reporter && !d.MemberKey(r.Reporter) {
			return r, ErrCatalog
		}
	default:
		return r, ErrCatalog
	}
	if !d.MemberKey(r.Reporter) {
		e, ok := d.Entry(r.Node)
		if r.Action != "installed" || !ok || e.Phase != membership.Learner || e.Peer.Key != hex.EncodeToString(r.Reporter[:]) {
			return r, ErrCatalog
		}
	}
	return r, nil
}
func (p Policy) reduceMemberReport(s state.State, d membership.Directory, cmd state.Command) (map[string][]byte, state.Code) {
	r, err := p.memberReport(s, cmd)
	if err != nil {
		return nil, state.Forbidden
	}
	switch r.Action {
	case "drain-move-start":
		return p.startDrainMove(s, d, r)
	case "identity-prepared", "identity-activate", "identity-installed", "identity-failed":
		row, _ := d.IdentityRotation(r.Node, r.Operation)
		if r.Action != "identity-installed" && r.Action != "identity-failed" && p.CheckIdentityEffect(s, row) != nil {
			return nil, state.Forbidden
		}
		switch r.Action {
		case "identity-failed":
			d, err = d.FailIdentityRotation(r.Node, r.Operation, r.IdentityFailure)
		case "identity-prepared":
			d, err = d.PrepareIdentityRotation(r.Node, r.Operation, *r.Identity)
		case "identity-activate":
			d, err = d.ActivateIdentityRotation(r.Node, r.Operation, s.Index()+1)
			if err == nil {
				return p.activateIdentityResources(s, d, row)
			}
		case "identity-installed":
			d, err = d.InstalledIdentityRotation(r.Node, r.Operation, s.Index()+1)
		}
	case "configuration":
		d, err = d.InstallConfiguration(*r.Configuration)
	case "recovered":
		d, err = d.RecoverConfiguration(*r.Recovery, *r.Configuration)
	case "restored":
		res, rerr := p.Resources(s)
		if rerr != nil {
			return nil, state.ConditionFailed
		}
		d, err = d.RestoreCluster(*r.Restore, r.Peer, res.Networks.TunnelAddressesInUse())
	case "node-proof":
		if r.Proof.Ready && p.CheckNodeEffect(s, r.Proof.Operation) != nil {
			return nil, state.Forbidden
		}
		owner, ownerErr := p.nodeOwner(s, r.Node)
		activity, activityErr := p.NodeActivity(s, owner)
		if ownerErr != nil || activityErr != nil || !activity.Empty() {
			return nil, state.ConditionFailed
		}
		d, err = d.ObserveNode(*r.Proof)
	case "remove-dispatch":
		if p.CheckNodeEffect(s, r.Operation) != nil {
			return nil, state.Forbidden
		}
		operation, _ := d.NodeOperation(r.Operation)
		if operation.Action != lifecycle.ForceRemove {
			owner, ownerErr := p.nodeOwner(s, r.Node)
			activity, activityErr := p.NodeActivity(s, owner)
			if ownerErr != nil || activityErr != nil || !activity.Empty() {
				return nil, state.ConditionFailed
			}
		}
		d, err = d.DispatchRemoval(r.Operation, r.Expected, r.ConfigurationIndex, r.Reporter)
	case "remove-unknown":
		d, err = d.UnknownRemoval(r.Operation, r.Expected)
	case "dispatch":
		if entry, ok := d.Entry(r.Node); ok && entry.Voting != nil && p.CheckVotingEffect(s, r.Node) != nil {
			return nil, state.Forbidden
		}
		if entry, ok := d.Entry(r.Node); ok && !p.vpsJoinAllowed(s, entry) {
			return nil, state.ConditionFailed
		}
		d, err = d.Dispatch(r.Node, r.Expected, r.JobID, r.ConfigurationIndex, r.Reporter)
	case "unknown":
		d, err = d.Unknown(r.Node, r.Expected, r.JobID)
	case "absent":
		d, err = d.Absent(r.Node, r.Expected, r.JobID, r.ConfigurationIndex)
	case "join-aborted":
		d, err = d.FinishAbortJoin(r.Node, r.Expected, r.ConfigurationIndex)
	case "observe":
		d, err = d.Observe(r.Node, r.Expected, r.JobID, r.ConfigurationIndex, r.Peer)
	case "installed":
		d, err = d.Installed(*r.Ack, r.Expected)
	case "vps-enroll":
		// The authority is the signed create-vps-node (or attach-owned-vps)
		// the server record came from; the reporter only attests the
		// source address.
		joinID, verr := p.vpsEnrollJoinID(s, r)
		res, rerr := p.Resources(s)
		if verr != nil || rerr != nil {
			return nil, state.ConditionFailed
		}
		d, err = d.Invite(r.Peer, joinID, res.Networks.TunnelAddressesInUse())
	}
	if err != nil {
		return nil, state.ConditionFailed
	}
	return p.memberCheckpoint(s, d)
}

func mustCurrentPeer(e membership.Entry) [32]byte {
	var key [32]byte
	raw, _ := hex.DecodeString(e.CurrentPeer().Key)
	copy(key[:], raw)
	return key
}
