// SPDX-License-Identifier: Apache-2.0

package buildinfo

import (
	"fmt"
	"strings"
	"testing"
)

func TestVersion(t *testing.T) {
	defer func(old string) { build = old }(build)
	code := fmt.Sprintf("%d.%d", Major, Minor)
	for _, c := range []struct {
		build, want string
		release     bool
	}{
		{"", code + ".0-dev", false},
		{"0", code + ".0", true},
		{"17", code + ".17", true},
		{"017", code + ".0-dev", false},
		{"x", code + ".0-dev", false},
		{"-1", code + ".0-dev", false},
	} {
		build = c.build
		if got := Version(); got != c.want || Release() != c.release {
			t.Errorf("build %q: Version() = %q, Release() = %v", c.build, got, Release())
		}
	}
	if Code() != code {
		t.Fatalf("Code() = %q", Code())
	}
	build = "4"
	if line := Line("sfcd"); !strings.HasPrefix(line, "sfcd "+code+".4") {
		t.Fatalf("Line = %q", line)
	}
}
