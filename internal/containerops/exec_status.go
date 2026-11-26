// SPDX-License-Identifier: Apache-2.0

package containerops

import "time"

// ExecStatus is an original execution observation, not an attach/restart token.
// Running nil means no current native observation; a retained finished receipt
// still proves its historical exit without asserting current container health.
type ExecStatus struct {
	Schema     uint8
	Request    string
	Target     Target
	Receipt    ExecReceipt
	Running    *bool `json:",omitempty"`
	ObservedAt time.Time
}
