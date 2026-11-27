// SPDX-License-Identifier: Apache-2.0

package state

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestNodeShellRefusalCodesKeepOriginalNumbersAndDeterministicReasons(t *testing.T) {
	if Applied != 0 || LedgerFull != 6 || NodeLastVoter != 7 || NodeStillResponding != 16 || NodeShellDisabled != 17 || NodeShellNotReady != 18 || NodeShellLimit != 19 || NodeShellUnreachable != 20 {
		t.Fatal("existing codes were renumbered or new shell codes were not appended")
	}
	for _, tc := range []struct {
		code   Code
		reason string
	}{{NodeShellDisabled, "node-shell-disabled"}, {NodeShellNotReady, "node-shell-not-ready"}, {NodeShellLimit, "limit"}, {NodeShellUnreachable, "node-unreachable"}, {NetworkSystemRange, "system-range-overlap"}, {BridgeExists, "bridge-exists"}, {BridgePeerClosed, "peer-closed"}, {NetworkChanging, "network-changing"}, {BridgeAttached, "bridge-attached"}} {
		if RejectionReason(tc.code) != tc.reason || !(Result{Code: tc.code, Reason: tc.reason}).ValidReason() || (Result{Code: tc.code}).ValidReason() || (Result{Code: ConditionFailed, Reason: tc.reason}).ValidReason() {
			t.Fatal("shell refusal reason was not fixed to its durable code", tc)
		}
	}
	if NetworkSystemRange != 21 || BridgeAttached != 25 {
		t.Fatal("the system range refusal was not appended")
	}
	if ValidResultCode(BridgeAttached+1) || (Result{Code: BridgeAttached + 1}).ValidReason() {
		t.Fatal("unknown future result code accepted")
	}
}

func TestNodeShellRefusalReceiptSurvivesPolicyMutationSnapshotAndReplay(t *testing.T) {
	for code := NodeShellDisabled; code <= NodeShellUnreachable; code++ {
		t.Run(RejectionReason(code), func(t *testing.T) {
			s, err := New("admin")
			if err != nil {
				t.Fatal(err)
			}
			command := Command{Kind: Module, Actor: "admin", Epoch: 1, RequestID: "original-shell", Key: "control/node-shell", Value: "original-signed-open"}
			s, refused, err := ApplyReduced(s, 1, command, nil, func(State, Command) (map[string][]byte, Code) { return nil, code })
			if err != nil || refused.Code != code || refused.Reason != RejectionReason(code) || !refused.ValidReason() || s.Object(command.Key).Present {
				t.Fatal("typed module refusal changed a resource or lost its reason", refused, err)
			}
			change := command
			change.RequestID, change.Value = "later-policy", "different-current-policy"
			s, changed, err := ApplyReduced(s, 2, change, nil, func(State, Command) (map[string][]byte, Code) {
				return map[string][]byte{change.Key: []byte(change.Value)}, Applied
			})
			if err != nil || changed.Code != Applied {
				t.Fatal("later independent policy mutation", changed, err)
			}
			raw, err := Encode(s)
			if err != nil {
				t.Fatal(err)
			}
			restored, err := Decode(raw)
			if err != nil {
				t.Fatal("typed refusal snapshot rejected", err)
			}
			if result, found := restored.LookupResult(command); !found || result != refused {
				t.Fatal("snapshot lost original refusal receipt", result)
			}
			before := restored.Object(command.Key)
			replayed, result, err := ApplyReduced(restored, 3, command, nil, nil)
			if err != nil || result != refused || replayed.Object(command.Key) != before {
				t.Fatal("original refusal was re-evaluated or changed after policy mutation", result, err)
			}
			for _, alter := range []func(*Result){func(r *Result) { r.Reason = "different" }, func(r *Result) { r.Reason = "" }, func(r *Result) { r.Code = NodeShellUnreachable + 1 }} {
				broken := rows(restored)
				found := false
				for i := range broken.Receipts {
					if broken.Receipts[i].ID == command.RequestID {
						alter(&broken.Receipts[i].Result)
						found = true
					}
				}
				if !found {
					t.Fatal("original snapshot receipt missing")
				}
				malformed, err := json.Marshal(broken)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = Decode(malformed); !errors.Is(err, ErrSnapshot) {
					t.Fatal("snapshot accepted an unbound/unknown refusal code or reason", err)
				}
			}
		})
	}
}
