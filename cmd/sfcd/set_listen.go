// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/jay94ks/seafield/internal/bootstrap"
	"github.com/jay94ks/seafield/internal/config"
)

// runSetListen is `sfcd set-listen`: after a joined server moved (its IP or
// port changed), the operator edits node.yaml `listen` to the new address
// and runs this with sfcd stopped. It accepts the new address in this
// server's own installation record, which otherwise refuses a node.yaml
// whose listen differs from the address it was installed with. The cluster
// side is `sfcli node set-endpoint NODE HOST:PORT`.
func runSetListen(args []string, globalConfig string, out, diagnostic io.Writer) int {
	f := flag.NewFlagSet("sfcd set-listen", flag.ContinueOnError)
	f.SetOutput(diagnostic)
	file := onceString{value: globalConfig, set: globalConfig != ""}
	f.Var(&file, "config", "managed node YAML file whose listen is the new address")
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return fail(diagnostic, err, 2)
	}
	if f.NArg() != 0 || file.value == "" {
		return fail(diagnostic, errors.New("set-listen requires --config and takes no arguments"), 2)
	}
	c, err := config.LoadNode(file.value)
	if err != nil {
		return fail(diagnostic, err, 2)
	}
	old, err := bootstrap.SetListen(c)
	if err != nil {
		return fail(diagnostic, err, 1)
	}
	fmt.Fprintf(out, "This server's address is now %s (was %s). If the cluster has not been told yet, run 'sfcli node set-endpoint %s %s'; then start sfcd.\n", c.Node.Listen, old, c.Node.ID, c.Node.Listen)
	return 0
}
