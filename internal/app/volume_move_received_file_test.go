// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/jay94ks/seafield/internal/reconcile"
)

func TestMoveReceivedFileRetainsNativeConsumerThroughUnknown(t *testing.T) {
	if reranUnprivileged(t) {
		return
	}
	b, backup, source, path := receiveFixture(t)
	ctx := context.Background()
	m := openReceiverFixture(t, path, b, backup)
	defer func() { _ = m.Close() }()
	if _, err := m.StepReceive(ctx, b, source, false); err != nil {
		t.Fatal(err)
	}
	unknown := errors.New("original native restore outcome unknown")
	if err := m.withReceivedMoveFile(ctx, b, source, func(file *os.File) error {
		if _, err := file.Stat(); err != nil {
			t.Fatal(err)
		}
		return unknown
	}); !errors.Is(err, unknown) {
		t.Fatal(err)
	}
	row, err := m.journal.Read(moveReceiveKey(b))
	if err != nil || len(row.Consumers) != 1 {
		t.Fatal("native consumer lost", err)
	}
	original := row.Consumers[moveRestoreConsumer(b)]
	if err = m.Close(); err != nil {
		t.Fatal(err)
	}
	m = openReceiverFixture(t, path, b, backup)
	if _, err = m.StepReceive(ctx, b, source, true); !errors.Is(err, reconcile.ErrLease) {
		t.Fatal("cleanup ignored uncertain native reader", err)
	}
	row, err = m.journal.Read(moveReceiveKey(b))
	if err != nil || row.Consumers[moveRestoreConsumer(b)] != original {
		t.Fatal("same original pin not recovered", err)
	}
	// The actual native consumer's independent verification/closure is tested
	// in the native integration. Here only the product pin contract is tested.
	if err = m.returnReceivedMoveFile(b); err != nil {
		t.Fatal(err)
	}
	if _, err = m.StepReceive(ctx, b, source, true); err != nil {
		t.Fatal(err)
	}
	if len(source.requests) != 1 {
		t.Fatal("native uncertainty recopied source")
	}
}
