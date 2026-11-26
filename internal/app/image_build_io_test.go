// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/imagebuild"
)

func TestBuildPartAppliedACKSkipsQueryAndUnknownOnlyRecoversOriginalSlot(t *testing.T) {
	latest := control.ImageBuildIOWork{Scope: imagebuild.UploadScope{Tenant: "tenant", Upload: "original", Creator: "manager"}, Expected: 7, Epoch: 1, RootRevision: 42, Index: 50}
	queries := 0
	revision, err := confirmedBuildPartRevision(latest, nil, func() (control.ImageBuildIOWork, error) {
		queries++
		return control.ImageBuildIOWork{}, context.Canceled
	})
	if err != nil || revision != 8 || queries != 0 {
		t.Fatal("exact Applied ACK performed a second permit query", revision, queries, err)
	}
	unknown := errors.New("original owner report ACK unknown")
	for _, test := range []struct {
		name string
		edit func(*control.ImageBuildIOWork) error
		want uint64
	}{
		{"confirmed", func(*control.ImageBuildIOWork) error { return nil }, 8},
		{"later-exact-slot", func(w *control.ImageBuildIOWork) error { w.Expected = 11; return nil }, 11},
		{"scope", func(w *control.ImageBuildIOWork) error { w.Scope.Upload = "other"; return nil }, 0},
		{"missing", func(w *control.ImageBuildIOWork) error { w.Recorded = false; return nil }, 0},
		{"older", func(w *control.ImageBuildIOWork) error { w.Expected = 6; return nil }, 0},
		{"denied", func(*control.ImageBuildIOWork) error { return context.Canceled }, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			queries := 0
			revision, err := confirmedBuildPartRevision(latest, unknown, func() (control.ImageBuildIOWork, error) {
				queries++
				confirmed := latest
				confirmed.Recorded, confirmed.Expected = true, 8
				failure := test.edit(&confirmed)
				return confirmed, failure
			})
			if queries != 1 || revision != test.want || test.want == 0 && !errors.Is(err, unknown) || test.want != 0 && err != nil {
				t.Fatal("original ACK uncertainty changed or queried repeatedly", revision, queries, err)
			}
		})
	}
}
