// SPDX-License-Identifier: Apache-2.0

package buildinfo

import (
	"regexp"
	"testing"
)

// Every numbered feature has a unique, report-safe name and a description.
func TestFeatureTableIsComplete(t *testing.T) {
	if len(featureNames) != len(featureDescriptions) || len(featureNames) > 64 {
		t.Fatal("feature table sizes", len(featureNames), len(featureDescriptions))
	}
	valid := regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	seen := map[string]bool{}
	for f := range featureNames {
		n, d := Feature(f).Name(), Feature(f).Description()
		if !valid.MatchString(n) || seen[n] || d == "" {
			t.Fatalf("feature %d: name %q description %q", f, n, d)
		}
		seen[n] = true
	}
}

func TestFeatureSetOperations(t *testing.T) {
	transit := Features(0).With(FeatureTransit)
	if !transit.Has(FeatureTransit) || Features(0).Has(FeatureTransit) || transit.And(0) != 0 || Feature(64).Name() != "" || Features(0).Has(64) {
		t.Fatal("set operations")
	}
	if got := transit.With(5).String(); got != "transit,#5" {
		t.Fatal(got)
	}
	if names := transit.With(5).Names(); len(names) != 1 || names[0] != "transit" {
		t.Fatal(names)
	}
	if Own.Names() != nil {
		t.Fatal("the 0.1.0 baseline announces no features", Own)
	}
}
