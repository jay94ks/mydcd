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

	"github.com/jay94ks/seafield/internal/cli"
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
		Name:  "sfcli",
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
			standaloneCommand(g),
			certificateCommand(g),
			domainCommand(g),
			vpsCommand(g),
			ingressCommand(g),
			lifecycleCommand(g),
			nodeCommand(g),
			clusterCommand(g),
			clusterFirewallCommandTree(g),
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
	return cli.OpenOps(filepath.Join(home, ".sfc", "ops"))
}

func newCommand(args []string) bool {
	// Global options may come first (sfcli --tenant shop node list). They
	// must all be new-frame options; an old-only option such as --config
	// keeps the whole line on the old commands.
	fs := flag.NewFlagSet("sfcli", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	(&globals{}).register(fs)
	if fs.Parse(args) != nil {
		return false
	}
	args = fs.Args()
	return len(args) != 0 && newRoot(&globals{}).Find(args[0]) != nil
}

// removedInputOptions are old global options with no new-command form: the
// only way to stop prompts is SFC_NONINTERACTIVE=1, and a script gives the
// wallet password in SFC_WALLET_PASSWORD_FILE (AGENTS.md, cli-and-formats).
var removedInputOptions = map[string]string{
	"no-input":           "--no-input is not an sfcli option; set SFC_NONINTERACTIVE=1 to never prompt",
	"wallet-password-fd": "--wallet-password-fd is not an sfcli option; put the wallet password in a mode 0600 file and set SFC_WALLET_PASSWORD_FILE to its path",
}

// oldUserCommands are the first words the old path still answers itself
// (runLegacy, runUserWithAccount). A line naming one with old options keeps
// working there until the final cleanup; every other new command is refused.
var oldUserCommands = map[string]bool{"login": true, "enroll-admin": true, "whoami": true, "logout": true, "server-version": true, "service-call": true, "compose": true, "manage": true, "wallet": true, "identity": true, "version": true}

// removedInputOption reports a removed input option given in front of a new
// command (sfcli --no-input node list). Without this check the line fell to
// the old commands, which answered "supported user commands: ..." for node.
func removedInputOption(args []string) (string, bool) {
	fs := flag.NewFlagSet("sfcli", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	(&globals{}).register(fs)
	fs.Bool("no-input", false, "")
	fs.String("wallet-password-fd", "", "")
	if fs.Parse(args) != nil {
		return "", false
	}
	rest := fs.Args()
	if len(rest) == 0 || newRoot(&globals{}).Find(rest[0]) == nil || oldUserCommands[rest[0]] {
		return "", false
	}
	message := ""
	fs.Visit(func(f *flag.Flag) {
		if m, ok := removedInputOptions[f.Name]; ok && message == "" {
			message = m
		}
	})
	return message, message != ""
}

func runNew(args []string, out, diagnostic io.Writer) int {
	// Ctrl-C cancels the command's context: a waiting command stops waiting
	// and leaves its operation ID; a second Ctrl-C ends the process.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	context.AfterFunc(ctx, stop)
	return cli.Execute(newRoot(&globals{}), args, cli.Env{Context: ctx, In: os.Stdin, Out: out, Err: diagnostic})
}
