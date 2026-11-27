// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
)

// appResendCommand resends the command of a deploy step whose first send
// was left unknown (for example the leader changed while it was sent). The
// cluster keeps each command's request ID, so a command that did arrive the
// first time is not applied twice: the server only collects its result.
func appResendCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	return &cli.Command{
		Name:  "resend",
		Args:  "APP [STEP]",
		Short: "Send a deploy step again after its send was left unknown",
		Long: `When a deploy shows "unknown", one of its steps was sent but the server could not tell whether it arrived.
resend sends the same step once more. A step that did arrive is not applied twice.
With one unknown step STEP may be left out; 'sfcli app show APP' and 'sfcli op show' list them.`,
		Flags: func(fs *flag.FlagSet) { fs.Var(&id, "id", "change `ID` (default: a new one)") },
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) < 1 || len(args) > 2 {
				return cli.Usagef("usage: sfcli app resend APP [STEP]")
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			ctx, cancel := g.Deadline(c)
			defer cancel()
			var inv appInventory
			if err := g.composeJSON(ctx, c, s, &inv, "status", "-p", args[0]); err != nil {
				return err
			}
			if len(inv.Apps) != 1 {
				return fmt.Errorf("no app named %s", args[0])
			}
			app := inv.Apps[0]
			reply, err := s.Client.AppOperation(ctx, s.Target, s.Stored.Session, tenant, control.AppOperationRequest{App: app.App, ID: app.Operation.ID})
			if err != nil {
				return err
			}
			view := reply.AppOperation
			if view == nil || !view.Found || !view.Current {
				return fmt.Errorf("%s has no current deploy", app.App)
			}
			step, err := pickUnknownStep(view.Unknown, args[1:])
			if err != nil {
				return err
			}
			if step.Resent {
				fmt.Fprintf(c.Out, "%s: step %s is already being sent again\n", app.App, step.Key)
				return nil
			}
			fmt.Fprintf(c.Err, "This sends step %s of the %s deploy (%s) again. If it already arrived it is not applied twice.\n", step.Key, app.App, view.ID)
			if err := g.Prompter(c).Confirm("Go ahead?"); err != nil {
				return err
			}
			op := id.Get()
			payload := control.AppStepReplay{Tenant: tenant, App: app.App, Operation: view.ID, Key: step.Key, Command: step.Command}
			if _, err = g.send(c, s, change{Summary: "app resend " + app.App + " " + step.Key, ID: op, Action: "resume-app-step", Expected: view.Revision, Payload: payload}); err != nil {
				return err
			}
			fmt.Fprintf(c.Out, "%s: step %s will be sent again (%s); 'sfcli app show %s' shows the deploy\n", app.App, step.Key, op, app.App)
			return nil
		}),
	}
}

// pickUnknownStep chooses the step named in args, or the only unknown one.
func pickUnknownStep(steps []deployment.UnknownStep, args []string) (deployment.UnknownStep, error) {
	if len(steps) == 0 {
		return deployment.UnknownStep{}, fmt.Errorf("no step of this deploy is unknown; nothing to resend")
	}
	if len(args) == 1 {
		for _, s := range steps {
			if s.Key == args[0] {
				return s, nil
			}
		}
		return deployment.UnknownStep{}, fmt.Errorf("step %s is not unknown; unknown steps: %s", args[0], unknownKeys(steps))
	}
	if len(steps) > 1 {
		return deployment.UnknownStep{}, cli.Usagef("several steps are unknown (%s); name one", unknownKeys(steps))
	}
	return steps[0], nil
}

func unknownKeys(steps []deployment.UnknownStep) string {
	keys := make([]string, len(steps))
	for i, s := range steps {
		keys[i] = s.Key
	}
	return strings.Join(keys, ", ")
}
