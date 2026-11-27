// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"errors"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/deployment"
)

// Only a bounded symbolic code crosses the authenticated plan boundary. Paths,
// source text and arbitrary error strings can contain private app inputs.
func validInputCode(code string) bool {
	if len(code) == 0 || len(code) > 64 {
		return false
	}
	for _, ch := range code {
		if ch != '_' && (ch < 'A' || ch > 'Z') && (ch < '0' || ch > '9') {
			return false
		}
	}
	return true
}

func appPlanErrorReply(err error) Reply {
	reply := Reply{Schema: 1, Code: "invalid"}
	if errors.Is(err, access.ErrDenied) {
		reply.Code = "denied"
	} else if errors.Is(err, access.ErrConflict) {
		reply.Code = "conflict"
	} else {
		var input *deployment.InputError
		if errors.As(err, &input) && validInputCode(input.Code) {
			reply.InputCode = input.Code
		}
	}
	return reply
}

func appPlanInputCause(reply Reply) error {
	if reply.Code != "ok" && validInputCode(reply.InputCode) {
		return &deployment.InputError{Code: reply.InputCode}
	}
	return nil
}
