// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/reconcile"
)

func TestBuildCleanupPendingDoesNotHideItsOriginalFailure(t *testing.T) {
	for _, err := range []error{reconcile.ErrPending, fmt.Errorf("cleanup: %w", reconcile.ErrPending), errors.Join(reconcile.ErrPending, errors.Join(reconcile.ErrPending))} {
		if !imageBuildOnlyPending(err) {
			t.Fatal("ordinary pending became a worker failure", err)
		}
	}
	for _, err := range []error{nil, imagebuild.ErrStorage, errors.Join(imagebuild.ErrStorage, reconcile.ErrPending), errors.Join(reconcile.ErrPending, fmt.Errorf("create: %w", imagebuild.ErrStorage)), errors.Join(context.DeadlineExceeded, reconcile.ErrPending)} {
		if imageBuildOnlyPending(err) {
			t.Fatal("cleanup pending hid the original failure", err)
		}
	}
}

func TestBuildWorkWaitReasonsDoNotBecomeCancellationOrPermissionFailure(t *testing.T) {
	for _, reason := range []string{"WAITING_FOR_CACHE", "WAITING_FOR_SLOT", "WAITING_FOR_BUDGET", "NOT_READY"} {
		if got := imageBuildBlockedCode(control.ImageBuildJobWork{Blocked: reason}); got != "" {
			t.Fatal(reason, got)
		}
	}
	for _, reason := range []string{"CANCELLED", "TIMEOUT", "PERMISSION_REVOKED"} {
		work := control.ImageBuildJobWork{Blocked: reason}
		if reason == "CANCELLED" {
			work.Run.Cancel = true
		}
		if got := imageBuildBlockedCode(work); got != reason {
			t.Fatal(reason, got)
		}
	}
}

func TestBuildFailureClassificationRetainsSafeOriginalCodes(t *testing.T) {
	for _, test := range []struct {
		err      error
		deadline bool
		code     string
	}{
		{imagebuild.ErrUntrustedBase, false, "UNTRUSTED_BASE"}, {imagebuild.ErrSourceFetch, false, "SOURCE_FETCH"},
		{imagebuild.ErrDigest, false, "STORAGE_UNAVAILABLE"}, {context.DeadlineExceeded, false, "TIMEOUT"},
		{errors.New("private daemon response must not be recorded"), false, "BUILD_FAILED"},
	} {
		result := imageBuildFailure(test.err, test.deadline)
		if result.Code != test.code || result.Image != "" || result.Bytes != 0 {
			t.Fatal(result)
		}
	}
}
