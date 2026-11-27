// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"testing"

	"github.com/jay94ks/seafield/internal/buildinfo"
)

func TestLdflags(t *testing.T) {
	code := fmt.Sprintf("%d.%d", buildinfo.Major, buildinfo.Minor)
	for _, c := range []struct {
		in, want string
		fail     bool
	}{
		{"v" + code + ".3", "-X github.com/jay94ks/seafield/internal/buildinfo.build=3", false},
		{code + ".0", "-X github.com/jay94ks/seafield/internal/buildinfo.build=0", false},
		{"v" + code + ".3-2-gabcdef1", "", false},
		{"v" + code + ".3-dirty", "", false},
		{"abcdef1", "", false},
		{"dev", "", false},
		{"", "", false},
		{fmt.Sprintf("v%d.%d.0", buildinfo.Major, buildinfo.Minor+1), "", true},
		{fmt.Sprintf("v%d.%d.0", buildinfo.Major+1, buildinfo.Minor), "", true},
		{"v" + code + ".01", "", false},
	} {
		got, err := ldflags(c.in)
		if (err != nil) != c.fail || got != c.want {
			t.Errorf("ldflags(%q) = %q, %v", c.in, got, err)
		}
	}
}
