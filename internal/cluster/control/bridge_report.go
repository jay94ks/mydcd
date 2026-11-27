// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/tenancy"
)

// BridgeClosedReport is a member server's virtual-bridge-closed report
// (devel/design/virtual-bridge.md 3): it removed a closing bridge's routes and
// rules from its own devices. Closure is signed with the node key, and so is
// the report. No user sends one, and it only settles a bridge a user already
// closed. RootRevision is the resources root it was read at.
type BridgeClosedReport struct {
	Schema              uint8
	Kind                string // "virtual-bridge-closed"
	Cluster, Reporter   [32]byte
	Epoch, RootRevision uint64
	Closure             tenancy.BridgeClosure
	Signature           []byte
}

const bridgeClosedKind = "virtual-bridge-closed"

func BridgeClosedReportBytes(r BridgeClosedReport) []byte {
	r.Signature = nil
	raw, _ := json.Marshal(r)
	return append([]byte("sfc-bridge-closed-report-1\x00"), raw...)
}

func (r BridgeClosedReport) Command() (state.Command, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return state.Command{}, err
	}
	cmd := state.Command{Kind: state.ModuleReport, Actor: "node/" + hex.EncodeToString(r.Reporter[:]), Epoch: r.Epoch, Key: ResourcesKey, Expected: r.RootRevision, Value: string(raw)}
	cmd.RequestID = state.ReportRequestID(cmd)
	_, err = state.EncodeCommand(cmd)
	return cmd, err
}

// bridgeClosedValue tells a bridge report from a system network report,
// which shares the resources root.
func bridgeClosedValue(raw string) bool {
	var head struct{ Kind string }
	return json.Unmarshal([]byte(raw), &head) == nil && head.Kind == bridgeClosedKind
}

func (p Policy) ResolveBridgeClosedReport(s state.State, caller [32]byte, raw []byte) (state.Command, error) {
	var r BridgeClosedReport
	if canonical(raw, &r) != nil || r.Reporter != caller {
		return state.Command{}, access.ErrDenied
	}
	cmd, err := r.Command()
	if err != nil {
		return cmd, err
	}
	_, err = p.bridgeClosedReport(s, cmd)
	return cmd, err
}

func (p Policy) bridgeClosedReport(s state.State, cmd state.Command) (BridgeClosedReport, error) {
	var r BridgeClosedReport
	if cmd.Kind != state.ModuleReport || cmd.Key != ResourcesKey || !strings.HasPrefix(cmd.Actor, "node/") || canonical([]byte(cmd.Value), &r) != nil || r.Schema != 1 || r.Kind != bridgeClosedKind || r.Cluster != p.Cluster || r.Closure.Cluster != p.Cluster || r.Closure.Key != r.Reporter || r.Epoch != s.ModuleEpoch() || !ed25519.Verify(r.Reporter[:], BridgeClosedReportBytes(r), r.Signature) {
		return r, ErrCatalog
	}
	want, err := r.Command()
	if err != nil || want != cmd {
		return r, ErrCatalog
	}
	// A server that is leaving still owes its report, so any current node.
	key, err := p.nodeOwner(s, r.Closure.Node)
	if err != nil || key != r.Reporter {
		return r, access.ErrDenied
	}
	return r, nil
}

func (p Policy) reduceBridgeClosedReport(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	current, err := p.Current(s)
	if err != nil {
		return nil, state.Invalid
	}
	p = current
	r, err := p.bridgeClosedReport(s, cmd)
	if err != nil {
		return nil, state.Forbidden
	}
	res, err := p.Resources(s)
	if err != nil {
		return nil, state.Invalid
	}
	if res.Networks, err = res.Networks.ObserveBridgeClosed(r.Closure); err != nil {
		return nil, state.ConditionFailed
	}
	return p.resourceCheckpoint(s, res)
}
