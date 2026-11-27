// SPDX-License-Identifier: Apache-2.0

// Package buildinfo is the build's version (devel/design/upgrades.md 3-1,
// 3-6). Major and Minor are source constants; only the build number comes
// from the linker:
//
//	-X github.com/jay94ks/seafield/internal/buildinfo.build=3
//
// tools/buildversion turns a release tag into that flag and refuses a tag
// whose major.minor differs from these constants. Without it the binary is a
// development build of this major.minor.
//
// The version is a name for people. Compatibility does not follow minor or
// build numbers: within a major every release keeps compatibility, and
// additive changes are gated on per-major feature bits (upgrades.md 3-1, 3-2).
package buildinfo

import (
	"fmt"
	"runtime/debug"
	"strconv"
)

// Major and Minor are the source's version. Major changes only for a
// release that may break compatibility; Minor is raised whenever the project
// wants a new version name while keeping compatibility.
const (
	Major = 0
	Minor = 1
)

// build is the release build number, set only by the linker.
var build string

// Release reports whether this is a release build (a build number was set).
func Release() bool {
	_, ok := buildNumber()
	return ok
}

func buildNumber() (uint64, bool) {
	if build == "" {
		return 0, false
	}
	n, err := strconv.ParseUint(build, 10, 32)
	if err != nil || strconv.FormatUint(n, 10) != build {
		return 0, false
	}
	return n, true
}

// Code is the code version, "major.minor".
func Code() string { return fmt.Sprintf("%d.%d", Major, Minor) }

// Version is "major.minor.build" for a release build and
// "major.minor.0-dev" for a development build.
func Version() string {
	if n, ok := buildNumber(); ok {
		return fmt.Sprintf("%d.%d.%d", Major, Minor, n)
	}
	return fmt.Sprintf("%d.%d.0-dev", Major, Minor)
}

// VCS is the source revision Go recorded at build time, if any.
type VCS struct {
	Commit   string // full revision
	Time     string // commit time, RFC 3339
	Modified bool   // the tree had uncommitted changes
}

// Source reads the revision Go recorded at build time. It is empty when the
// binary was built outside a repository (for example in a Docker build
// without .git).
func Source() VCS {
	var v VCS
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return v
	}
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			v.Commit = s.Value
		case "vcs.time":
			v.Time = s.Value
		case "vcs.modified":
			v.Modified = s.Value == "true"
		}
	}
	return v
}

// Line is the one-line answer of a `version` command, such as
// "sfcd 0.1.3 (commit 1a2b3c4d5e6f)" or "sfcd 0.1.0-dev (commit 1a2b3c4d5e6f, modified)".
func Line(program string) string {
	s := program + " " + Version()
	v := Source()
	if v.Commit == "" {
		return s
	}
	commit := v.Commit
	if len(commit) > 12 {
		commit = commit[:12]
	}
	if v.Modified {
		return s + " (commit " + commit + ", modified)"
	}
	return s + " (commit " + commit + ")"
}
