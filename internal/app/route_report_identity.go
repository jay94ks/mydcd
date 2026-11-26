// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/network/services"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/storage"
)

// Replacing an authenticated coordination envelope does not settle its prior
// submission. Keep its exact signed report/command and native preparation as
// immutable unknown provenance in the ORIGINAL observations DB. These rows are
// never a replay queue and never cause native or user-operation execution.
type routeReportTrace struct {
	Schema                          uint8
	Outcome                         string
	Reference                       [32]byte
	Nonce                           [32]byte
	Core                            json.RawMessage
	Dispatch                        services.RouteDispatch
	Bridge                          reconcile.Lease
	NativeStarted                   bool
	NativeBoot                      [32]byte
	BridgeReturned, NeverDispatched bool
	Report                          json.RawMessage
	Command                         state.Command
}

func routeReportTraceKey(reference [32]byte, raw []byte) string {
	digest := sha256.Sum256(raw)
	return "route-report-trace/" + hex.EncodeToString(reference[:]) + "/" + hex.EncodeToString(digest[:])
}

func sameRouteReport(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

func (r *Runtime) routeReportTraceWrites(ref services.ReferenceConsumer, original, next routeOwnerRecord) (map[string][]byte, error) {
	writes := map[string][]byte{}
	archive := func(report any, command state.Command) error {
		raw, err := json.Marshal(report)
		if err != nil {
			return err
		}
		trace := routeReportTrace{Schema: 1, Outcome: "unknown", Reference: ref.ID, Nonce: original.Nonce, Core: original.Core, Dispatch: original.Dispatch, Bridge: original.Bridge, NativeStarted: original.NativeStarted, NativeBoot: original.NativeBoot, BridgeReturned: original.BridgeReturned, NeverDispatched: original.NeverDispatched, Report: raw, Command: command}
		encoded, err := json.Marshal(trace)
		if err != nil || len(encoded) > 34<<20 {
			return errors.New("route report trace exceeds original observation budget")
		}
		key := routeReportTraceKey(ref.ID, raw)
		prior, err := r.reports.GetBounded(key, 34<<20)
		if err == nil && !bytes.Equal(prior, encoded) {
			return errors.New("immutable original route report trace conflicts")
		}
		if err != nil && !errors.Is(err, storage.ErrMissing) {
			return err
		}
		writes[key] = encoded
		return nil
	}
	if original.Report != nil && !sameRouteReport(original.Report, next.Report) {
		command, err := original.Report.Command()
		if err != nil {
			return nil, err
		}
		if err = archive(original.Report, command); err != nil {
			return nil, err
		}
	}
	if original.Retirement != nil && !sameRouteReport(original.Retirement, next.Retirement) {
		command, err := original.Retirement.Command()
		if err != nil {
			return nil, err
		}
		if err = archive(original.Retirement, command); err != nil {
			return nil, err
		}
	}
	return writes, nil
}
