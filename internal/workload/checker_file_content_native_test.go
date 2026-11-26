// SPDX-License-Identifier: Apache-2.0

package workload_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/jay94ks/mydcd/internal/workload"
	contract "github.com/jay94ks/mydcd/lifecycle/v1"
)

func exerciseContainerFileContent(t *testing.T, ctx context.Context, manager *workload.Manager, lease workload.ReadProbeLease) {
	t.Helper()
	digest := sha256.Sum256([]byte("ready\n"))
	q := contract.FileProbe{Service: "fixture", Path: "/lifecycle-ready", Kind: "regular", ContentDigest: hex.EncodeToString(digest[:]), MaxBytes: 32}
	allow := func(context.Context) error { return nil }
	if got, err := manager.ReadProbeFile(ctx, lease, q, allow); err != nil || !got.Exists || !got.Match {
		t.Fatal("actual Docker content match", got, err)
	}
	other := sha256.Sum256([]byte("wrong"))
	q.ContentDigest = hex.EncodeToString(other[:])
	if got, err := manager.ReadProbeFile(ctx, lease, q, allow); err != nil || got.Match {
		t.Fatal("actual Docker content mismatch", got, err)
	}
	q.ContentDigest = hex.EncodeToString(digest[:])
	q.MaxBytes = 2
	if _, err := manager.ReadProbeFile(ctx, lease, q, allow); !errors.Is(err, workload.ErrProbeFileContent) {
		t.Fatal("file budget ignored", err)
	}
	q.MaxBytes = 32
	calls := 0
	denied := errors.New("current authority revoked")
	if _, err := manager.ReadProbeFile(ctx, lease, q, func(context.Context) error {
		calls++
		if calls == 3 {
			return denied
		}
		return nil
	}); !errors.Is(err, denied) || calls != 3 {
		t.Fatal("content returned after revocation", err, calls)
	}
}
