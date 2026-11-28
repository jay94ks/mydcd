// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// SKILL.md is the guide for AI agents that run sfcli (cmd/sfcli/SKILL.md). The
// CLI package installs it next to the executable (an archive) or under
// share/sfc beside the bin directory (/usr/local/share/sfc/SKILL.md).
func skillCandidates(exe string) []string {
	dir := filepath.Dir(exe)
	return []string{filepath.Join(dir, "SKILL.md"), filepath.Join(dir, "..", "share", "sfc", "SKILL.md")}
}

// skillPath is the installed SKILL.md, or "" with the place a package puts it.
func skillPath(exe string) (found, expected string) {
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	candidates := skillCandidates(exe)
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			return filepath.Clean(p), ""
		}
	}
	return "", filepath.Clean(candidates[1])
}

func skillHelp(out io.Writer) {
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintln(out, "AI agents: read SKILL.md from the sfcli CLI package before running sfc.")
		return
	}
	if found, expected := skillPath(exe); found != "" {
		fmt.Fprintf(out, "AI agents: read %s before running sfc.\n", found)
	} else {
		fmt.Fprintf(out, "AI agents: SKILL.md (how to run sfcli safely) is not installed; the CLI package puts it at %s.\n", expected)
	}
}
