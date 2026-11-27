// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/state"

	"github.com/hashicorp/raft"
)

func TestRealInstalledConfigurationReadsPublishedGenerationDuringWriter(t *testing.T) {
	f := sourceCatalogBoundary(t)
	original, err := f.engine.InstalledConfiguration(f.ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	f.engine.fsm.mu.Lock()
	defer f.engine.fsm.mu.Unlock()
	// The writer is intentionally held throughout the read; a context cannot
	// cancel an RWMutex wait. Only the already synced generation may be read.
	type outcome struct {
		view InstalledConfiguration
		err  error
	}
	finished := make(chan outcome, 1)
	ctx, cancel := context.WithTimeout(f.ctx, 50*time.Millisecond)
	defer cancel()
	go func() {
		view, err := f.engine.InstalledConfiguration(ctx, false)
		finished <- outcome{view, err}
	}()
	select {
	case got := <-finished:
		if got.err != nil || got.view.Index != original.Index || got.view.AppliedIndex < original.AppliedIndex || !bytes.Equal(raft.EncodeConfiguration(got.view.Configuration), raft.EncodeConfiguration(original.Configuration)) {
			t.Fatal("installed configuration did not retain its durable proof", got.err)
		}
	case <-time.After(150 * time.Millisecond):
		t.Fatal("installed configuration blocked behind unrelated FSM writer")
	}
}

// sourceCatalogBoundary is a control fixture without the user catalog module.
func sourceCatalogBoundary(t *testing.T) *controlBoundary {
	t.Helper()
	return newControlBoundary(t, func(f *controlBoundary) {
		f.options.Manifest = [32]byte{21}
		f.options.ModuleID, f.options.Reduce, f.options.AdmitModule = [32]byte{}, nil, nil
		f.options.Validate = func(state.State, state.State, state.Command) error { return nil }
	})
}
