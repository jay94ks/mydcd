// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/sfcp"
)

func TestTransportDiagnosticPreservesCauseAndDelivery(t *testing.T) {
	for _, tc := range []struct {
		cause error
		name  string
	}{
		{context.DeadlineExceeded, "deadline"}, {context.Canceled, "canceled"},
		{os.ErrDeadlineExceeded, "io-deadline"}, {sfcp.ErrAdmission, "admission"},
		{sfcp.ErrFrame, "frame"}, {sfcp.ErrBudget, "budget"},
		{sfcp.ErrTruncated, "truncated"}, {io.ErrUnexpectedEOF, "unexpected-eof"},
		{io.EOF, "eof"}, {net.ErrClosed, "closed"}, {errors.New("private-value"), "other"},
	} {
		for _, phase := range []sfcp.Phase{sfcp.NotSent, sfcp.Unknown} {
			cause := fmt.Errorf("private-value: %w", tc.cause)
			err := &Error{Code: "transport", Phase: phase, Cause: cause, stage: "receive"}
			message := err.Error()
			if strings.Contains(message, "private-value") || !strings.Contains(message, "stage=receive cause="+tc.name+" ") ||
				!errors.Is(err, tc.cause) || err.Cause != cause || err.Phase != phase {
				t.Fatalf("diagnostic changed delivery/cause or leaked data: %s", message)
			}
		}
	}
	if got := (&Error{Code: "denied", Phase: sfcp.Completed, Cause: errors.New("private-value"), stage: "receive"}).Error(); got != "user request: denied" {
		t.Fatal("authorization outcome reclassified", got)
	}
}
