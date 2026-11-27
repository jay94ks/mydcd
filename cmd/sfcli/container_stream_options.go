// SPDX-License-Identifier: Apache-2.0

package main

import "github.com/jay94ks/seafield/internal/containerops"

func expandContainerExecFlags(args []string) []string {
	var out []string
	for i, arg := range args {
		if arg == "--" {
			return append(out, args[i:]...)
		}
		if arg == "-it" || arg == "-ti" {
			out = append(out, "-i", "-t")
		} else {
			out = append(out, arg)
		}
	}
	return out
}
func containerExecFlag(name string) bool {
	return name == "instance" || name == "i" || name == "interactive" || name == "t" || name == "tty"
}
func (o *containerCLIOptions) execSpec() containerops.ExecSpec {
	s := containerops.ExecSpec{Argv: o.argv, Stdin: o.interactive.value, TTY: o.tty.value}
	if s.TTY {
		s.Rows, s.Cols = 24, 80
	}
	return s
}
func composeStreaming(o composeOptions) bool {
	return o.method == "exec" || o.method == "exec-status" || o.container != nil && containerReadMethod(o.method) && (o.container.follow.value || o.container.watch.value)
}
