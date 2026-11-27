// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/jay94ks/seafield/internal/storage"
)

func TestNodeCensusRetainsRQ9UnknownFileJournalWithoutInventingNativeClose(t *testing.T) {
	for _, phase := range []string{"intent", "pinned", "applying", "completed", "returned", "invalid"} {
		t.Run(phase, func(t *testing.T) {
			db, err := storage.Open(filepath.Join(t.TempDir(), "observations.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			r := &Runtime{reports: db}
			if err := r.saveVolumeFile(volumeFileOwner{Schema: 1, ID: "original-file", Phase: phase}); err != nil {
				t.Fatal(err)
			}
			activity, err := r.nodeLocalActivity(context.Background())
			if phase == "invalid" {
				if err == nil {
					t.Fatal("unknown original phase became empty native census")
				}
				return
			}
			if err != nil || activity.Empty() != (phase == "returned") {
				t.Fatal("unsettled original file work omitted", activity, err)
			}
		})
	}
}
