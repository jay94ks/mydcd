// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/sfcp"
)

func TestPlanRejectionKeepsOnlySymbolicInputCode(t *testing.T) {
	for _, code := range []string{"VOLUME_NOT_MOVABLE", "INVALID_FIELD", "bad\ncode", strings.Repeat("X", 65), ""} {
		r := appPlanErrorReply(&deployment.InputError{Code: code, Path: "private-value"})
		raw, err := json.Marshal(r)
		if err != nil || strings.Contains(string(raw), "private-value") {
			t.Fatal("plan reply exposed a private path", err)
		}
		cause := appPlanInputCause(r)
		if validInputCode(code) {
			var input *deployment.InputError
			if !errors.As(cause, &input) || input.Code != code || input.Path != "" || !strings.Contains((&Error{Code: r.Code, Phase: sfcp.Completed, Cause: cause}).Error(), code) {
				t.Fatal("safe planner code lost", cause)
			}
		} else if cause != nil || r.InputCode != "" {
			t.Fatal("arbitrary text admitted as a planner code")
		}
	}
	for _, tc := range []struct {
		err  error
		code string
	}{{access.ErrDenied, "denied"}, {access.ErrConflict, "conflict"}, {errors.New("private-value"), "invalid"}} {
		r := appPlanErrorReply(tc.err)
		if r.Code != tc.code || r.InputCode != "" || appPlanInputCause(r) != nil {
			t.Fatal("authority/unknown failure reclassified", r.Code)
		}
	}
}
