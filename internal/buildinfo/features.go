// SPDX-License-Identifier: Apache-2.0

package buildinfo

import (
	"encoding/binary"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Feature is one version of one feature set (Jay 2026-11-28: nodes compare a
// per-major internal feature set instead of version numbers).
//
//   - Group (uint8) sorts similar feature sets; it decides nothing by itself.
//   - Set (uint8, within its group) is one capability. A build announces every
//     version of it that it speaks, so its list is its compatible range.
//   - Version (uint16) is the unit of compatibility: a frame, a Raft entry or
//     an API field added by v2 is used only when both ends (or every member)
//     announce v2.
//   - Postfix (a short string such as "preview") marks a version outside the
//     compatibility promise: it is used only when both ends announce exactly
//     the same feature, may change or vanish in the next build, and is never
//     written into Raft. The stable version takes over when it lands.
//
// It is written group-set-vN[-postfix] with the table's names, such as
// network-transit-v1 or network-transit-v1-preview. The numbers make one
// 32-bit code (Code: group, set, version from the top byte down), so a
// version range of one set is a plain integer comparison (Range); the wire
// carries the code and the postfix (Encode).
//
// Matching (Jay 2026-11-28 08:32 KST): no postfix means the postfix
// "mainline" (Mainline), and two features match only with the same postfix.
// Mainline versions are compared by code, so a range of them is an integer
// comparison; any other postfix matches only the same code exactly, and no
// range includes it. Mainline is stored as the empty postfix: it is never
// written out, and Normalize turns an explicit "mainline" into "".
// Postfixes are case-insensitive and always written in lowercase.
//
// Rules within a major: numbers and names, once used, keep their meaning
// and are never reused; everything a build of this major can do without a
// feature is the major's baseline (0.1.0); the next major starts a new
// table. A build may stop announcing a set's oldest versions (the minimum
// may rise within a major, but only in a release that raises minor, or in
// any release for an urgent fix such as a security flaw; Jay 2026-11-28
// 08:33–08:34 KST), and the table keeps every version ever
// defined so its numbers stay taken. Features are live per node: peers
// exchange them in the SFCP handshake and the cluster's set is the intersection over its members,
// computed in memory, never stored in Raft (devel/design/upgrades.md 3-1).
type Feature struct {
	Group   uint8
	Set     uint8
	Version uint16
	Postfix string
}

// The major-0 group and set numbers.
const (
	GroupNetwork uint8 = 1

	SetNetworkTransit uint8 = 1
)

var groupNames = map[uint8]string{
	GroupNetwork: "network",
}

var setNames = map[[2]uint8]string{
	{GroupNetwork, SetNetworkTransit}: "transit",
}

// The major-0 feature table.
var (
	// NetworkTransitV1: transit sessions through another member (SFCP
	// purpose 25, Observation kind 21; devel/design/sfcp-transit.md).
	// Planned for 0.1.1; not in Own until it exists.
	NetworkTransitV1 = Feature{GroupNetwork, SetNetworkTransit, 1, ""}
)

var featureTable = []struct {
	f    Feature
	desc string
}{
	{NetworkTransitV1, "transit sessions through another member (SFCP purpose 25)"},
}

// Own is the feature set this build implements. The 0.1.0 baseline has none.
var Own = Features{}

// Limits on an announced set.
const (
	MaxFeatures = 64
	MaxPostfix  = 16
)

var postfixRE = regexp.MustCompile(`^[a-z][a-z0-9]{0,15}$`)

// Mainline is the postfix a feature without one has.
const Mainline = "mainline"

// PostfixName is f's postfix, Mainline when it has none.
func (f Feature) PostfixName() string {
	if f.Postfix == "" {
		return Mainline
	}
	return f.Postfix
}

// Normalize lowercases the postfix (postfixes are case-insensitive and
// always written in lowercase, Jay 2026-11-28 08:45 KST) and stores an
// explicit Mainline postfix as the empty one.
func (f Feature) Normalize() Feature {
	f.Postfix = strings.ToLower(f.Postfix)
	if f.Postfix == Mainline {
		f.Postfix = ""
	}
	return f
}

// Valid reports whether f can be announced: a version from 1 and an empty
// or lowercase postfix.
func (f Feature) Valid() bool {
	return f.Version != 0 && (f.Postfix == "" || len(f.Postfix) <= MaxPostfix && postfixRE.MatchString(f.Postfix))
}

// Stable reports whether f is a mainline version, inside the compatibility
// promise.
func (f Feature) Stable() bool { return f.Normalize().Postfix == "" }

// SameSet reports whether f and o are versions of one feature set.
func (f Feature) SameSet(o Feature) bool { return f.Group == o.Group && f.Set == o.Set }

// Code is the 32-bit code: group in bits 31–24, set in 23–16, version in
// 15–0. Codes of one set sort by version.
func (f Feature) Code() uint32 {
	return uint32(f.Group)<<24 | uint32(f.Set)<<16 | uint32(f.Version)
}

// FeatureOf is the feature with the given code and postfix.
func FeatureOf(code uint32, postfix string) Feature {
	return Feature{uint8(code >> 24), uint8(code >> 16), uint16(code), postfix}
}

func compareFeatures(a, b Feature) int {
	if a.Code() != b.Code() {
		if a.Code() < b.Code() {
			return -1
		}
		return 1
	}
	return strings.Compare(a.Postfix, b.Postfix)
}

// Range is a version range of one feature set, From to To inclusive, as
// codes. It holds stable versions only: a postfixed feature is matched
// exactly, never by a range.
type Range struct{ From, To uint32 }

// Versions is the range of versions from..to of the set (group, set).
func Versions(group, set uint8, from, to uint16) Range {
	return Range{Feature{group, set, from, ""}.Code(), Feature{group, set, to, ""}.Code()}
}

// From is the range of f's set from f's version up: the need of a frame or
// field that f introduced.
func From(f Feature) Range { return Versions(f.Group, f.Set, f.Version, 0xffff) }

// Contains reports whether f is a stable version inside r. A range that
// spans two sets contains nothing.
func (r Range) Contains(f Feature) bool {
	c := f.Code()
	return f.Stable() && r.From>>16 == r.To>>16 && c>>16 == r.From>>16 && r.From <= c && c <= r.To
}

// GroupName is the group's name in this build's table, or "g<N>".
func GroupName(g uint8) string {
	if n, ok := groupNames[g]; ok {
		return n
	}
	return "g" + strconv.Itoa(int(g))
}

// SetName is the feature set's written name ("network-transit"), with
// "g<N>"/"s<N>" for numbers this build does not know.
func SetName(group, set uint8) string {
	n, ok := setNames[[2]uint8{group, set}]
	if !ok {
		n = "s" + strconv.Itoa(int(set))
	}
	return GroupName(group) + "-" + n
}

// String is the written form, group-set-vN[-postfix].
func (f Feature) String() string {
	s := SetName(f.Group, f.Set) + "-v" + strconv.Itoa(int(f.Version))
	if f.Postfix != "" {
		s += "-" + f.Postfix
	}
	return s
}

// Known reports whether this build's table has f.
func (f Feature) Known() bool { return f.Description() != "" }

// Description is a one-line description of f from this build's table, or ""
// when this build does not know it.
func (f Feature) Description() string {
	for _, e := range featureTable {
		if e.f == f {
			return e.desc
		}
	}
	return ""
}

// Table lists this major's known features in order.
func Table() []Feature {
	out := make([]Feature, 0, len(featureTable))
	for _, e := range featureTable {
		out = append(out, e.f)
	}
	slices.SortFunc(out, compareFeatures)
	return out
}

// Features is a set of features. The zero value is the empty set. It is
// comparable: two sets are equal exactly when they hold the same features.
type Features struct {
	// enc is the canonical wire encoding (EncodeFeatures).
	enc string
}

// NewFeatures makes a set; ok is false when a feature is invalid or the set
// is larger than an announcement may be.
func NewFeatures(list ...Feature) (Features, bool) {
	list = slices.Clone(list)
	for i := range list {
		list[i] = list[i].Normalize()
	}
	slices.SortFunc(list, compareFeatures)
	list = slices.Compact(list)
	if len(list) > MaxFeatures {
		return Features{}, false
	}
	var b []byte
	for _, f := range list {
		if !f.Valid() {
			return Features{}, false
		}
		b = binary.LittleEndian.AppendUint32(b, f.Code())
		b = append(b, byte(len(f.Postfix)))
		b = append(b, f.Postfix...)
	}
	return Features{enc: string(b)}, true
}

// MustFeatures is NewFeatures for constant tables; it panics on a bad entry.
func MustFeatures(list ...Feature) Features {
	s, ok := NewFeatures(list...)
	if !ok {
		panic("buildinfo: invalid feature set")
	}
	return s
}

// List is the set's features in order.
func (s Features) List() []Feature {
	var out []Feature
	b := []byte(s.enc)
	for len(b) >= 5 {
		n := int(b[4])
		out = append(out, FeatureOf(binary.LittleEndian.Uint32(b), string(b[5:5+n])))
		b = b[5+n:]
	}
	return out
}

// Names are the written names in order (node reports carry them).
func (s Features) Names() []string {
	var out []string
	for _, f := range s.List() {
		out = append(out, f.String())
	}
	return out
}

// Empty reports whether s has no features.
func (s Features) Empty() bool { return s.enc == "" }

// Has reports whether f is in s.
func (s Features) Has(f Feature) bool { return slices.Contains(s.List(), f.Normalize()) }

// HasAll reports whether every feature of need is in s.
func (s Features) HasAll(need Features) bool {
	have := s.List()
	for _, f := range need.List() {
		if !slices.Contains(have, f) {
			return false
		}
	}
	return true
}

// And is the intersection of s and o.
func (s Features) And(o Features) Features {
	other := o.List()
	var both []Feature
	for _, f := range s.List() {
		if slices.Contains(other, f) {
			both = append(both, f)
		}
	}
	r, _ := NewFeatures(both...)
	return r
}

// Or is the union of s and o; ok is false when it would be too large.
func (s Features) Or(o Features) (Features, bool) {
	return NewFeatures(append(s.List(), o.List()...)...)
}

// Best is the highest stable version of the feature set (group, set) in s,
// or 0 when s has none of it. Postfixed versions never count.
func (s Features) Best(group, set uint8) uint16 {
	var best uint16
	for _, f := range s.List() {
		if f.Group == group && f.Set == set && f.Stable() && f.Version > best {
			best = f.Version
		}
	}
	return best
}

// Within reports whether s has a version inside r (stable only).
func (s Features) Within(r Range) bool {
	for _, f := range s.List() {
		if r.Contains(f) {
			return true
		}
	}
	return false
}

// Meets reports whether s has a version inside every range of needs.
func (s Features) Meets(needs ...Range) bool {
	for _, r := range needs {
		if !s.Within(r) {
			return false
		}
	}
	return true
}

// String is the written names joined by ','.
func (s Features) String() string { return strings.Join(s.Names(), ",") }

// Encode is the handshake form: for each feature in order, its 32-bit code
// little endian, the postfix length u8 and the postfix bytes.
// The empty set encodes as zero bytes.
func (s Features) Encode() []byte { return []byte(s.enc) }

// DecodeFeatures reads the handshake form. Only the canonical encoding is
// accepted (valid entries, in order, unique, within the limits).
func DecodeFeatures(b []byte) (Features, bool) {
	var list []Feature
	rest := b
	for len(rest) > 0 {
		if len(rest) < 5 || len(rest) < 5+int(rest[4]) || len(list) == MaxFeatures {
			return Features{}, false
		}
		n := int(rest[4])
		list = append(list, FeatureOf(binary.LittleEndian.Uint32(rest), string(rest[5:5+n])))
		rest = rest[5+n:]
	}
	s, ok := NewFeatures(list...)
	if !ok || s.enc != string(b) {
		return Features{}, false
	}
	return s, true
}

// ParseFeature reads a written name with this build's table; ok is false
// for a malformed name or a group/set name the table does not have.
func ParseFeature(name string) (Feature, bool) {
	m := writtenRE.FindStringSubmatch(name)
	if m == nil {
		return Feature{}, false
	}
	v, err := strconv.ParseUint(m[2], 10, 16)
	if err != nil {
		return Feature{}, false
	}
	for k := range setNames {
		if SetName(k[0], k[1]) == m[1] {
			f := Feature{k[0], k[1], uint16(v), m[3]}.Normalize()
			return f, f.Valid()
		}
	}
	if g, s, ok := numberedSet(m[1]); ok {
		f := Feature{g, s, uint16(v), m[3]}.Normalize()
		return f, f.Valid()
	}
	return Feature{}, false
}

var writtenRE = regexp.MustCompile(`^([a-z0-9]+-[a-z0-9-]+?)-v([1-9][0-9]{0,4})(?:-([A-Za-z][A-Za-z0-9]{0,15}))?$`)

// numberedSet reads "g<N>-s<M>" (or a known group with "s<M>").
func numberedSet(name string) (uint8, uint8, bool) {
	gs, ss, ok := strings.Cut(name, "-")
	if !ok || !strings.HasPrefix(ss, "s") {
		return 0, 0, false
	}
	var g uint64
	var err error
	found := false
	for n, gname := range groupNames {
		if gname == gs {
			g, found = uint64(n), true
		}
	}
	if !found {
		if !strings.HasPrefix(gs, "g") {
			return 0, 0, false
		}
		if g, err = strconv.ParseUint(gs[1:], 10, 8); err != nil || fmt.Sprint(g) != gs[1:] {
			return 0, 0, false
		}
	}
	s, err := strconv.ParseUint(ss[1:], 10, 8)
	if err != nil || fmt.Sprint(s) != ss[1:] {
		return 0, 0, false
	}
	return uint8(g), uint8(s), true
}
