// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/raft"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
)

func TestCheckerAuthorityDiagnosticDistinguishesUnavailableFromDenied(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{nil, ""},
		{fmt.Errorf("wrapped: %w", context.DeadlineExceeded), "deadline"},
		{raft.ErrLeadershipLost, "leadership-lost"},
		{errNoAppLeader, "no-leader"},
		{fmt.Errorf("private-provider-secret: %w", errAppLeaderPeerUnavailable), "management-transport"},
		{access.ErrDenied, "denied"},
		{fmt.Errorf("wrapped: %w", &cluster.ManagementError{Code: "not-leader", Message: "private-provider-secret"}), "management-not-leader"},
		{&cluster.ManagementError{Code: "unavailable", Message: "private-provider-secret"}, "management-unavailable"},
		{&cluster.ManagementError{Code: "denied", Message: "private-provider-secret"}, "management-denied"},
		{&cluster.ManagementError{Code: "private-provider-secret", Message: "private-provider-secret"}, "error"},
		{errors.New("private-provider-secret"), "error"},
	} {
		code := checkerAuthorityErrorCode(tc.err)
		if code != tc.want || !validCheckerAuthorityError(code) {
			t.Fatalf("diagnostic code=%q want=%q", code, tc.want)
		}
		d := checkerRunDiagnostic{Phase: "compiled-run", Cause: "error", AuthorityCause: "error", AuthorityError: code}
		raw, err := json.Marshal(d)
		var restored checkerRunDiagnostic
		if err != nil || strings.Contains(string(raw), "private-provider-secret") || json.Unmarshal(raw, &restored) != nil || restored != d || !restored.valid() {
			t.Fatal("diagnostic lost bounded provenance or leaked raw error")
		}
	}
}

func TestCheckerAuthorityDiagnosticReadsExistingRecordsAndRejectsRawErrors(t *testing.T) {
	var old checkerRunDiagnostic
	if json.Unmarshal([]byte(`{"Phase":"yaegi-run","Cause":"error","AuthorityCause":"error","AuthorityCalls":2}`), &old) != nil || old.AuthorityError != "" || !old.valid() {
		t.Fatal("pre-existing observation requires unchanged decoding")
	}
	old.AuthorityError = "arbitrary provider error with private input"
	if old.valid() {
		t.Fatal("unbounded error entered a retained diagnostic")
	}
}
