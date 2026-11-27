// SPDX-License-Identifier: Apache-2.0

package buildinfo

import (
	"strconv"
	"strings"
)

// Feature is one bit in this major's feature table (Jay 2026-11-28: nodes
// compare a per-major internal feature set instead of version numbers).
//
// Rules within a major:
//   - A number, once given, keeps its name and meaning; it is never reused
//     or removed. The next major starts a new table.
//   - Everything a build of this major can do without a feature bit is the
//     major's baseline (0.1.0); a feature bit names something added later.
//   - Features are live per node: peers exchange them in the SFCP handshake
//     and the cluster's set is the intersection over its members, computed
//     in memory, never stored in Raft.
type Feature uint8

// Features is a set of Feature bits.
type Features uint64

// The major-0 feature table.
const (
	// FeatureTransit: transit sessions through another member (SFCP purpose
	// 25, Observation kind 21; devel/design/sfcp-transit.md). Planned for
	// 0.1.1; not in Own until it exists.
	FeatureTransit Feature = 0
)

var featureNames = [...]string{
	FeatureTransit: "transit",
}

var featureDescriptions = [...]string{
	FeatureTransit: "transit sessions through another member (SFCP purpose 25)",
}

// Own is the feature set this build implements. The 0.1.0 baseline has none.
const Own Features = 0

// Has reports whether f is in s.
func (s Features) Has(f Feature) bool { return f < 64 && s&(1<<f) != 0 }

// With returns s with f added.
func (s Features) With(f Feature) Features { return s | 1<<f }

// And is the intersection of s and o.
func (s Features) And(o Features) Features { return s & o }

// Name is f's name in this major's table, or "" when this build does not
// know the number.
func (f Feature) Name() string {
	if int(f) < len(featureNames) {
		return featureNames[f]
	}
	return ""
}

// Description is a one-line description of f, or "" when unknown.
func (f Feature) Description() string {
	if int(f) < len(featureDescriptions) {
		return featureDescriptions[f]
	}
	return ""
}

// Names lists the names of the set's features this build knows, in number
// order. Node reports carry it, so readers need not share this table.
func (s Features) Names() []string {
	var names []string
	for f := Feature(0); f < 64; f++ {
		if s.Has(f) && f.Name() != "" {
			names = append(names, f.Name())
		}
	}
	return names
}

// String lists the set's names, sorted by number; a bit this build does not
// know shows as its number.
func (s Features) String() string {
	var names []string
	for f := Feature(0); f < 64; f++ {
		if !s.Has(f) {
			continue
		}
		if n := f.Name(); n != "" {
			names = append(names, n)
		} else {
			names = append(names, "#"+strconv.Itoa(int(f)))
		}
	}
	return strings.Join(names, ",")
}
