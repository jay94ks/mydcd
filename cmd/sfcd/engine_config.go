// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/engineconf"
)

// runEngineConfig writes this server's engine daemon.json from node.yaml
// (or prints it with --output -). The node package runs it before sfed
// starts; a change takes effect when sfed restarts.
func runEngineConfig(args []string, file string, out, diagnostic io.Writer) int {
	f := flag.NewFlagSet("engine-config", flag.ContinueOnError)
	f.SetOutput(diagnostic)
	output := f.String("output", engineconf.DefaultPath, "where to write daemon.json, or - for standard output")
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return fail(diagnostic, err, 2)
	}
	if f.NArg() != 0 || file == "" {
		return fail(diagnostic, errors.New("usage: sfcd --config NODE.yaml engine-config [--output FILE|-]"), 2)
	}
	c, err := config.LoadNode(file)
	if err != nil {
		return fail(diagnostic, err, 2)
	}
	if *output == "-" {
		b, err := engineconf.Render(c.Engine)
		if err != nil {
			return fail(diagnostic, err, 2)
		}
		_, err = out.Write(b)
		if err != nil {
			return fail(diagnostic, err, 1)
		}
		return 0
	}
	changed, err := engineconf.Write(*output, c.Engine)
	if err != nil {
		return fail(diagnostic, err, 1)
	}
	if changed {
		fmt.Fprintf(out, "wrote %s; restart sfed to apply it\n", *output)
	}
	return 0
}
