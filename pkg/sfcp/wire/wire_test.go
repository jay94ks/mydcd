// SPDX-License-Identifier: Apache-2.0

package wire

import (
	"bytes"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

var testRules = Rules(func(p Purpose, kind uint8) (Rule, bool) {
	switch {
	case p == 1 && kind == 1:
		return Rule{Fields: []int{-1, 4}, Budget: 64}, true
	case p == 6 && kind == 1:
		return Rule{Budget: 64, NoRequest: true}, true
	}
	return Rule{}, false
})

func TestRoundTripAndRules(t *testing.T) {
	f := Frame{Purpose: 1, Kind: 1, Request: 7, Fields: []Field{{1, true, []byte("x")}, {2, true, []byte("abcd")}, {128, false, []byte("ext")}}}
	var buf bytes.Buffer
	if err := testRules.WriteFrame(&buf, f); err != nil {
		t.Fatal(err)
	}
	got, err := testRules.ReadFrame(&buf, MaxBody)
	if err != nil || got.Request != 7 || len(got.Fields) != 3 || string(got.Fields[2].Value) != "ext" {
		t.Fatal(got, err)
	}
	for _, bad := range []Frame{
		{Purpose: 1, Kind: 2, Request: 1},                                                                                       // unknown kind
		{Purpose: 1, Kind: 1, Request: 0, Fields: f.Fields},                                                                     // missing request ID
		{Purpose: 6, Kind: 1, Request: 1},                                                                                       // datagram with request ID
		{Purpose: 1, Kind: 1, Request: 1, Fields: []Field{{1, true, []byte("x")}}},                                              // missing field
		{Purpose: 1, Kind: 1, Request: 1, Fields: []Field{{1, true, []byte("x")}, {2, true, []byte("abc")}}},                    // wrong length
		{Purpose: 1, Kind: 1, Request: 1, Fields: []Field{{1, true, bytes.Repeat([]byte("x"), 80)}, {2, true, []byte("abcd")}}}, // over budget
	} {
		if _, err := testRules.Encode(bad); err == nil {
			t.Fatalf("encoded %+v", bad)
		}
	}
	d, _ := testRules.NewDecoder(MaxBody)
	b, _ := testRules.Encode(f)
	for i := range b {
		if fr, _, err := d.Feed(b[i : i+1]); err != nil || (fr != nil) != (i == len(b)-1) {
			t.Fatal(i, fr, err)
		}
	}
	if d.Close() != nil {
		t.Fatal("clean close")
	}
}

// The package must stay copyable into the engine: standard library only.
func TestStandardLibraryOnly(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	for _, name := range files {
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(token.NewFileSet(), name, src, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			if strings.Contains(strings.SplitN(path, "/", 2)[0], ".") {
				t.Fatalf("%s imports %s", name, path)
			}
		}
	}
}
