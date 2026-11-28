// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"errors"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/buildinfo"
	"github.com/jay94ks/seafield/internal/cluster/state"
)

// An entry using a feature this build lacks halts the FSM with a message
// naming the feature, and the leader never submits one.
func TestEntryFeaturesThisBuildLacks(t *testing.T) {
	if err := haveFeatures(7, state.Command{}); err != nil {
		t.Fatal("baseline entry", err)
	}
	c := state.Command{Features: buildinfo.MustFeatures(buildinfo.Feature{Group: 200, Set: 1, Version: 1})}
	err := haveFeatures(812, c)
	if !errors.Is(err, ErrUnknownFeature) || !strings.Contains(err.Error(), "entry 812 uses g200-s1-v1, which this server (sfcd") || !strings.Contains(err.Error(), buildinfo.Version()) {
		t.Fatal(err)
	}
	if err := (&Engine{}).submitFeatures(c); !errors.Is(err, ErrFeatureUnavailable) {
		t.Fatal("submitted a feature this build lacks", err)
	}
	if err := (&Engine{}).submitFeatures(state.Command{}); err != nil {
		t.Fatal(err)
	}
}

// A snapshot or backup whose entries used a feature this build lacks is
// refused.
func TestStateFeaturesThisBuildLacks(t *testing.T) {
	s, err := state.New("admin")
	if err != nil {
		t.Fatal(err)
	}
	if err := haveStateFeatures(s); err != nil {
		t.Fatal("baseline state", err)
	}
	c := state.Command{Actor: "admin", Epoch: 1, RequestID: "1", Key: "workload/a", Value: "x", Features: buildinfo.MustFeatures(buildinfo.Feature{Group: 200, Set: 1, Version: 1})}
	s, r, err := state.Apply(s, 1, c)
	if err != nil || r.Code != state.Applied {
		t.Fatal(r, err)
	}
	if err := haveStateFeatures(s); !errors.Is(err, ErrUnknownFeature) || !strings.Contains(err.Error(), "this state uses g200-s1-v1") {
		t.Fatal(err)
	}
}
