// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/jay94ks/mydcd/internal/cli"
)

// The command tree of devel/design/cli-and-formats.md. While the commands
// move, run hands a command line here when its first word is a new
// top-level command; each group PR adds its group to newRoot and deletes the
// old commands it replaces.

// globals are the options every new command accepts (see session.go).
type globals struct {
	output                cli.FormatFlag
	context, tenant, user string
	reason                string
	timeout               time.Duration
	yes, noInput          bool

	// session is for tests only: when set, withSession and opSession use it
	// instead of logging in, and do not close it.
	session *session
}

func newRoot(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "mydc",
		Flags: g.register,
		Sub: []*cli.Command{
			contextCommand(g),
			keyCommand(g),
			loginCommand(g),
			logoutCommand(g),
			whoamiCommand(g),
			enrollCommand(g),
			versionCommand(g),
			appCommand(g),
			cli.OpCommand(openOps, &g.output, handlers(g)),
			tenantCommand(g),
			userCommand(g),
			networkCommand(g),
			routeCommand(g),
			volumeCommand(g),
			registryCommand(g),
			imageCommand(g),
			buildCommand(g),
			secretCommand(g),
			cdCommand(g),
			certificateCommand(g),
			domainCommand(g),
			ingressCommand(g),
			lifecycleCommand(g),
			nodeCommand(g),
			clusterCommand(g),
			eventsCommand(g),
		},
	}
}

// opKinds settles each kind of operation with the server. Each group
// registers its kinds from an init function in its own file; the handler
// gets the parsed global options so it can open a session (g.opSession).
var opKinds = map[string]func(*globals) cli.Handler{}

func handlers(g *globals) map[string]cli.Handler {
	out := make(map[string]cli.Handler, len(opKinds))
	for kind, h := range opKinds {
		out[kind] = h(g)
	}
	return out
}

func openOps() (*cli.Ops, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	return cli.OpenOps(filepath.Join(home, ".mydc", "ops"))
}

func newCommand(args []string) bool {
	// Global options may come first (mydc --tenant shop node list). They
	// must all be new-frame options; an old-only option such as --config
	// keeps the whole line on the old commands.
	fs := flag.NewFlagSet("mydc", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	(&globals{}).register(fs)
	if fs.Parse(args) != nil {
		return false
	}
	args = fs.Args()
	return len(args) != 0 && newRoot(&globals{}).Find(args[0]) != nil
}

func runNew(args []string, out, diagnostic io.Writer) int {
	// Ctrl-C cancels the command's context: a waiting command stops waiting
	// and leaves its operation ID; a second Ctrl-C ends the process.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	context.AfterFunc(ctx, stop)
	return cli.Execute(newRoot(&globals{}), args, cli.Env{Context: ctx, In: os.Stdin, Out: out, Err: diagnostic})
}
