// SPDX-License-Identifier: Apache-2.0

package control

import (
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"strings"
	"unicode/utf8"
)

// Reason is signed display metadata. ApprovedBy is the submitter's label, not
// proof of that account's approval or a substitute for independent signatures.
type OperationReason struct {
	Text       string `json:",omitempty"`
	IncidentID string `json:",omitempty"`
	ApprovedBy string `json:",omitempty"`
}

func (r OperationReason) Valid() bool {
	return utf8.ValidString(r.Text) && utf8.RuneCountInString(r.Text) <= 512 && !strings.ContainsRune(r.Text, 0) && len(r.IncidentID) <= 128 && utf8.ValidString(r.IncidentID) && !strings.ContainsAny(r.IncidentID, "\x00\r\n") && (r.ApprovedBy == "" || lifecycle.ValidID(r.ApprovedBy))
}
