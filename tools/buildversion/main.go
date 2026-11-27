// SPDX-License-Identifier: Apache-2.0

// Command buildversion prints the Go linker flags that put a build's version
// into the binaries (devel/design/upgrades.md 3-6):
//
//	go run ./tools/buildversion VERSION
//
// VERSION is what the Makefile has: a release tag (vX.Y.Z) or anything else,
// such as `git describe` output. A release tag must match the source code
// version internal/buildinfo.Major/Minor, or the command fails so the build
// stops. Anything else is a development build and prints no flags.
package main

import (
	"fmt"
	"os"
	"regexp"
	"strconv"

	"github.com/jay94ks/seafield/internal/buildinfo"
)

var releaseTag = regexp.MustCompile(`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: buildversion VERSION")
		os.Exit(2)
	}
	flags, err := ldflags(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "buildversion:", err)
		os.Exit(1)
	}
	fmt.Println(flags)
}

func ldflags(version string) (string, error) {
	m := releaseTag.FindStringSubmatch(version)
	if m == nil {
		return "", nil
	}
	major, err1 := strconv.ParseUint(m[1], 10, 32)
	minor, err2 := strconv.ParseUint(m[2], 10, 32)
	build, err3 := strconv.ParseUint(m[3], 10, 32)
	if err1 != nil || err2 != nil || err3 != nil {
		return "", fmt.Errorf("version %q is out of range", version)
	}
	if major != buildinfo.Major || minor != buildinfo.Minor {
		return "", fmt.Errorf("tag %s is version %d.%d but the source is %s; change internal/buildinfo or the tag", version, major, minor, buildinfo.Code())
	}
	return fmt.Sprintf("-X github.com/jay94ks/seafield/internal/buildinfo.build=%d", build), nil
}
