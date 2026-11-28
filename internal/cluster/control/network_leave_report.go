// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/tenancy"
)

// NetworkLeaveReport is a server's own leave from a workspace network it was
// drained from (devel/design/managed-tun-networks.md, 한 서버씩 떼기). A user
// drained the member with drain-network; once the server's native sources
// are gone it sends its signed closure itself, so a network delete or a
// server removal finishes on the cluster even when the client that started
// it stops. No user sends one, and it only settles a drain a user already
// made. Expected is the member's revision; RootRevision is the resources
// root it was read at.
type NetworkLeaveReport struct {
	Schema                        uint8
	Kind                          string // "network-leave"
	Cluster, Reporter             [32]byte
	Expected, Epoch, RootRevision uint64
	Closure                       tenancy.NetworkClosure
	Signature                     []byte
}

const networkLeaveKind = "network-leave"

func NetworkLeaveReportBytes(r NetworkLeaveReport) []byte {
	r.Signature = nil
	raw, _ := json.Marshal(r)
	return append([]byte("sfc-network-leave-report-1\x00"), raw...)
}

func (r NetworkLeaveReport) Command() (state.Command, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return state.Command{}, err
	}
	cmd := state.Command{Kind: state.ModuleReport, Actor: "node/" + hex.EncodeToString(r.Reporter[:]), Epoch: r.Epoch, Key: ResourcesKey, Expected: r.RootRevision, Value: string(raw)}
	cmd.RequestID = state.ReportRequestID(cmd)
	_, err = state.EncodeCommand(cmd)
	return cmd, err
}

func (p Policy) ResolveNetworkLeaveReport(s state.State, caller [32]byte, raw []byte) (state.Command, error) {
	var r NetworkLeaveReport
	if canonical(raw, &r) != nil || r.Reporter != caller {
		return state.Command{}, access.ErrDenied
	}
	cmd, err := r.Command()
	if err != nil {
		return cmd, err
	}
	_, err = p.networkLeaveReport(s, cmd)
	return cmd, err
}

func (p Policy) networkLeaveReport(s state.State, cmd state.Command) (NetworkLeaveReport, error) {
	var r NetworkLeaveReport
	if cmd.Kind != state.ModuleReport || cmd.Key != ResourcesKey || !strings.HasPrefix(cmd.Actor, "node/") || canonical([]byte(cmd.Value), &r) != nil || r.Schema != 1 || r.Kind != networkLeaveKind || r.Cluster != p.Cluster || r.Closure.Cluster != p.Cluster || r.Closure.Owner != r.Reporter || r.Closure.Tenant == "" || r.Epoch != s.ModuleEpoch() || !ed25519.Verify(r.Reporter[:], NetworkLeaveReportBytes(r), r.Signature) {
		return r, ErrCatalog
	}
	want, err := r.Command()
	if err != nil || want != cmd {
		return r, ErrCatalog
	}
	// A server that is leaving the cluster still owes its leave, so any
	// current node.
	key, err := p.nodeOwner(s, r.Closure.Node)
	if err != nil || key != r.Reporter {
		return r, access.ErrDenied
	}
	return r, nil
}

func (p Policy) reduceNetworkLeaveReport(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	current, err := p.Current(s)
	if err != nil {
		return nil, state.Invalid
	}
	p = current
	r, err := p.networkLeaveReport(s, cmd)
	if err != nil {
		return nil, state.Forbidden
	}
	res, err := p.Resources(s)
	if err != nil {
		return nil, state.Invalid
	}
	proof := r.Closure
	var native map[string][]byte
	res.Networks, native, err = p.leaveMember(s, res, proof, r.Expected, func(a services.Authority, sources []services.RetiredNativeSource) (services.Authority, tenancy.Networks, error) {
		return a.LeaveDrainedTUN(res.Networks, proof, sources)
	})
	if errors.Is(err, access.ErrDenied) {
		return nil, state.Forbidden
	}
	if err != nil {
		return nil, state.ConditionFailed
	}
	writes, code := p.resourceCheckpoint(s, res)
	if code != state.Applied {
		return nil, code
	}
	for key, raw := range native {
		writes[key] = raw
	}
	return writes, code
}
