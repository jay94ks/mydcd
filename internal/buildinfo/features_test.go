// SPDX-License-Identifier: Apache-2.0

package buildinfo

import (
	"strings"
	"testing"
)

// Every table entry is valid, unique and described; the table holds every
// mainline version below its highest (numbers stay taken even after builds
// stop announcing old ones); the 0.1.0 baseline announces nothing.
func TestFeatureTableIsComplete(t *testing.T) {
	seen := map[Feature]bool{}
	for _, e := range featureTable {
		if !e.f.Valid() || seen[e.f] || e.desc == "" {
			t.Fatalf("feature %v: description %q", e.f, e.desc)
		}
		if _, ok := groupNames[e.f.Group]; !ok {
			t.Fatalf("%v: group has no name", e.f)
		}
		if _, ok := setNames[[2]uint8{e.f.Group, e.f.Set}]; !ok {
			t.Fatalf("%v: set has no name", e.f)
		}
		seen[e.f] = true
	}
	for f := range seen {
		for v := uint16(1); f.Stable() && v < f.Version; v++ {
			if lower := (Feature{f.Group, f.Set, v, ""}); !seen[lower] {
				t.Fatalf("%v without %v", f, lower)
			}
		}
	}
	if _, ok := NewFeatures(Table()...); !ok {
		t.Fatal("table is not a valid set")
	}
	if !Own.Empty() {
		t.Fatal("the 0.1.0 baseline announces no features", Own)
	}
	for _, f := range Own.List() {
		if !f.Known() {
			t.Fatalf("Own has %v outside the table", f)
		}
	}
}

func TestFeatureCodeAndNames(t *testing.T) {
	f := Feature{GroupNetwork, SetNetworkTransit, 2, "preview"}
	if f.Code() != 0x01010002 || FeatureOf(f.Code(), "preview") != f {
		t.Fatalf("code %08x", f.Code())
	}
	if f.String() != "network-transit-v2-preview" || NetworkTransitV1.String() != "network-transit-v1" {
		t.Fatal(f.String(), NetworkTransitV1.String())
	}
	if (Feature{7, 3, 1, ""}).String() != "g7-s3-v1" || (Feature{GroupNetwork, 9, 4, ""}).String() != "network-s9-v4" {
		t.Fatal("numbered names")
	}
	for _, c := range []struct {
		name string
		want Feature
		ok   bool
	}{
		{"network-transit-v1", NetworkTransitV1, true},
		{"network-transit-v1-preview", Feature{1, 1, 1, "preview"}, true},
		{"network-transit-v65535", Feature{1, 1, 65535, ""}, true},
		{"g7-s3-v12", Feature{7, 3, 12, ""}, true},
		{"network-s9-v4", Feature{1, 9, 4, ""}, true},
		{"network-transit-v1-mainline", NetworkTransitV1, true},
		{"network-transit-v65536", Feature{}, false},
		{"network-transit-v0", Feature{}, false},
		{"network-transit-v01", Feature{}, false},
		{"network-transit", Feature{}, false},
		{"Network-transit-v1", Feature{}, false},
		{"unknown-transit-v1", Feature{}, false},
		{"g256-s1-v1", Feature{}, false},
		{"g07-s1-v1", Feature{}, false},
		{"network-transit-v1-Preview", Feature{1, 1, 1, "preview"}, true},
		{"network-transit-v1-MAINLINE", NetworkTransitV1, true},
		{"network-transit-v1-pre_view", Feature{}, false},
		{"", Feature{}, false},
	} {
		got, ok := ParseFeature(c.name)
		if ok != c.ok || ok && got != c.want {
			t.Errorf("%q: %+v %v", c.name, got, ok)
		}
		if ok && !strings.EqualFold(got.String(), c.name) && !strings.EqualFold(got.String()+"-mainline", c.name) {
			t.Errorf("%q written back as %q", c.name, got)
		}
	}
	if MustFeatures(Feature{1, 1, 1, "Preview"}) != MustFeatures(Feature{1, 1, 1, "preview"}) || !MustFeatures(Feature{1, 1, 1, "PREVIEW"}).Has(Feature{1, 1, 1, "preview"}) {
		t.Fatal("postfixes are case-insensitive")
	}
	if NetworkTransitV1.PostfixName() != Mainline || f.PostfixName() != "preview" || MustFeatures(Feature{1, 1, 1, Mainline}) != MustFeatures(NetworkTransitV1) {
		t.Fatal("mainline")
	}
	if (Feature{1, 1, 0, ""}).Valid() || (Feature{1, 1, 1, "x-y"}).Valid() || !(Feature{1, 1, 1, "rc2"}).Valid() {
		t.Fatal("validity")
	}
}

func TestFeatureRanges(t *testing.T) {
	r := Versions(GroupNetwork, SetNetworkTransit, 2, 4)
	for _, c := range []struct {
		f  Feature
		in bool
	}{
		{Feature{1, 1, 1, ""}, false},
		{Feature{1, 1, 2, ""}, true},
		{Feature{1, 1, 4, ""}, true},
		{Feature{1, 1, 5, ""}, false},
		{Feature{1, 1, 3, "preview"}, false}, // a postfix only matches exactly
		{Feature{1, 2, 3, ""}, false},
		{Feature{2, 1, 3, ""}, false},
	} {
		if r.Contains(c.f) != c.in {
			t.Errorf("%v in %v: %v", c.f, r, !c.in)
		}
	}
	if (Range{Feature{1, 1, 1, ""}.Code(), Feature{1, 2, 1, ""}.Code()}).Contains(Feature{1, 1, 9, ""}) {
		t.Fatal("a range across sets contains nothing")
	}
	if !From(NetworkTransitV1).Contains(Feature{1, 1, 65535, ""}) || From(Feature{1, 1, 2, ""}).Contains(NetworkTransitV1) {
		t.Fatal("from")
	}
	if !MustFeatures(Feature{1, 1, 2, ""}).Meets(r, From(NetworkTransitV1)) || MustFeatures(Feature{1, 1, 2, ""}).Meets(r, From(Feature{1, 2, 1, ""})) || !(Features{}).Meets() {
		t.Fatal("meets")
	}
	if !MustFeatures(Feature{1, 1, 1, ""}, Feature{1, 1, 3, ""}).Within(r) || MustFeatures(Feature{1, 1, 3, "preview"}).Within(r) {
		t.Fatal("within")
	}
}

func TestFeatureSetOperations(t *testing.T) {
	v1, v2, pre := NetworkTransitV1, Feature{1, 1, 2, ""}, Feature{1, 1, 3, "preview"}
	a := MustFeatures(v2, v1, pre, v1)
	b := MustFeatures(v1, pre)
	if a.String() != "network-transit-v1,network-transit-v2,network-transit-v3-preview" {
		t.Fatal(a)
	}
	if !a.Has(v2) || b.Has(v2) || a.Has(Feature{1, 1, 3, "beta"}) || !a.HasAll(b) || b.HasAll(a) || !a.HasAll(Features{}) {
		t.Fatal("membership")
	}
	if a.And(b) != b || a.And(Features{}) != (Features{}) || (Features{}).And(a) != (Features{}) {
		t.Fatal("intersection")
	}
	if MustFeatures(pre).And(MustFeatures(Feature{1, 1, 3, "beta"})) != (Features{}) {
		t.Fatal("postfixes intersect only when equal")
	}
	if u, ok := b.Or(MustFeatures(v2)); !ok || u != a {
		t.Fatal("union", u)
	}
	if a.Best(1, 1) != 2 || b.Best(1, 1) != 1 || MustFeatures(pre).Best(1, 1) != 0 || a.Best(1, 2) != 0 {
		t.Fatal("best")
	}
	if (Features{}).List() != nil || (Features{}).Names() != nil || !(Features{}).Empty() {
		t.Fatal("empty set")
	}
	if _, ok := NewFeatures(Feature{1, 1, 0, ""}); ok {
		t.Fatal("invalid feature accepted")
	}
	many := make([]Feature, MaxFeatures+1)
	for i := range many {
		many[i] = Feature{1, 1, uint16(i + 1), ""}
	}
	if _, ok := NewFeatures(many...); ok {
		t.Fatal("limit")
	}
	if len(MustFeatures(many[:MaxFeatures]...).List()) != MaxFeatures {
		t.Fatal("full set")
	}
}

func TestFeatureEncoding(t *testing.T) {
	a := MustFeatures(NetworkTransitV1, Feature{1, 1, 2, "preview"})
	want := "\x01\x00\x01\x01\x00" + "\x02\x00\x01\x01\x07preview"
	if string(a.Encode()) != want {
		t.Fatalf("encoding %x", a.Encode())
	}
	got, ok := DecodeFeatures(a.Encode())
	if !ok || got != a {
		t.Fatal("round trip", got, ok)
	}
	if got, ok := DecodeFeatures(nil); !ok || !got.Empty() {
		t.Fatal("empty")
	}
	v1 := "\x01\x00\x01\x01\x00"
	v2 := "\x02\x00\x01\x01\x00"
	for _, bad := range []string{
		v2 + v1,                        // not sorted
		v1 + v1,                        // duplicate
		"\x00\x00\x01\x01\x00",         // version 0
		v1[:4],                         // short entry
		"\x01\x00\x01\x01\x03pr",       // postfix cut
		"\x01\x00\x01\x01\x02P1",       // bad postfix
		"\x01\x00\x01\x01\x08mainline", // mainline is written as no postfix
		"\x01\x00\x01\x01\x02Rc",       // the wire carries lowercase only
	} {
		if _, ok := DecodeFeatures([]byte(bad)); ok {
			t.Errorf("%x accepted", bad)
		}
	}
	var long []byte
	for i := 0; i <= MaxFeatures; i++ {
		long = append(long, Feature{1, 1, uint16(i + 1), ""}.encodeOne()...)
	}
	if _, ok := DecodeFeatures(long); ok {
		t.Fatal("too many accepted")
	}
}

func (f Feature) encodeOne() []byte { return MustFeatures(f).Encode() }
