// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/jay94ks/mydcd/internal/cli"
	"github.com/jay94ks/mydcd/internal/cliprofile"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/ingress"
	"github.com/jay94ks/mydcd/internal/userauth"
)

// The app commands run the app flows that the old compose command had
// (compose*.go: plan, upload, approvals, wait, container reads) with the
// session of the new command line. Each command builds the flow's argument
// list; the flows move into these commands in the final cleanup.

// composeFlow runs one compose flow in the session's tenant. Its JSON goes
// to out and its reasons to c.Err; a non-zero exit becomes cli.ExitError
// with the same code (4: the outcome is not known yet).
func (g *globals) composeFlow(ctx context.Context, c *cli.Context, s *session, out io.Writer, args ...string) error {
	tenant, err := g.Tenant(s, true)
	if err != nil {
		return err
	}
	args = append([]string{"--tenant", tenant}, args...)
	if code := runComposeDefaults(ctx, args, s.Client, s.Target, s.Stored, s.Home, cliprofile.Selection{}, out, c.Err); code != 0 {
		return cli.ExitError{Code: code}
	}
	return nil
}

// composeJSON runs a flow and decodes its JSON reply into v.
func (g *globals) composeJSON(ctx context.Context, c *cli.Context, s *session, v any, args ...string) error {
	var buf bytes.Buffer
	err := g.composeFlow(ctx, c, s, &buf, args...)
	if err != nil {
		// A failed flow still replies, so a caller can read the status.
		if v != nil {
			_ = json.Unmarshal(buf.Bytes(), v)
		}
		return err
	}
	if v != nil && json.Unmarshal(buf.Bytes(), v) != nil {
		return errors.New("unexpected reply from the app flow")
	}
	return nil
}

func appCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "app",
		Short: "Deploy apps from app.yaml and look after their containers",
		Long: `An app is one app.yaml (Compose file with x-mydc settings) deployed in a
tenant. FILE defaults to app.yaml (or compose.yaml) in this directory.`,
		Sub: []*cli.Command{
			appListCommand(g),
			appShowCommand(g),
			appCheckCommand(g),
			appDiffCommand(g),
			appDeployCommand(g),
			appDownCommand(g),
			appHistoryCommand(g),
			appSourceCommand(g),
			appLogsCommand(g),
			appExecCommand(g),
			appRestartCommand(g),
			appClearLogsCommand(g),
			appSampleCommand(g, "top", "Show the processes of a service's container"),
			appSampleCommand(g, "stats", "Show a service's container resource use"),
			appInspectCommand(g),
		},
	}
}

type appInventory struct {
	Tenant string
	Apps   []control.AppView
}

func appStatus(v control.AppView) string {
	if v.Retirement != nil {
		if v.Retirement.Status == "Retired" {
			return "down"
		}
		return "going down"
	}
	return strings.ToLower(v.Operation.Status)
}

func appListCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "list",
		Short: "List the apps of the tenant",
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 0 {
				return cli.Usagef("list takes no arguments")
			}
			ctx, cancel := g.Deadline(c)
			defer cancel()
			var inv appInventory
			if err := g.composeJSON(ctx, c, s, &inv, "ps"); err != nil {
				return err
			}
			if inv.Apps == nil {
				inv.Apps = []control.AppView{}
			}
			return cli.Print(c.Out, g.output.Format(), inv.Apps, func() cli.Rows {
				t := cli.Rows{Header: []string{"app", "revision", "status", "health", "cd"}}
				for _, v := range inv.Apps {
					cd := ""
					if v.CD != nil {
						cd = "on"
						if v.CD.Paused {
							cd = "paused"
						}
					}
					t.Add(v.App, v.Revision, appStatus(v), strings.ToLower(v.Health), cd)
				}
				return t
			})
		}),
	}
}

func appShowCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "show",
		Args:  "APP",
		Short: "Show one app's deployment, health and CD state",
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 1 {
				return cli.Usagef("show needs one app name")
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
			v := inv.Apps[0]
			return cli.Print(c.Out, g.output.Format(), v, func() cli.Rows {
				t := cli.Rows{Header: []string{"field", "value"}}
				t.Add("app", v.App)
				t.Add("tenant", v.Tenant)
				t.Add("deployment", v.Deployment)
				t.Add("revision", v.Revision)
				t.Add("status", appStatus(v))
				t.Add("health", strings.ToLower(v.Health))
				t.Add("operation", v.Operation.ID)
				if v.Operation.CompletedAt > 0 {
					t.Add("completed", time.Unix(int64(v.Operation.CompletedAt), 0).Local().Format("2006-01-02 15:04"))
				}
				if v.Retirement != nil {
					t.Add("down operation", v.Retirement.ID)
				}
				if v.CD != nil {
					cd := "on"
					if v.CD.Paused {
						cd = "paused"
					}
					t.Add("cd", cd)
				}
				return t
			})
		}),
	}
}

// appCheckCommand reads app.yaml without the server.
func appCheckCommand(g *globals) *cli.Command {
	var file string
	return &cli.Command{
		Name:  "check",
		Short: "Check app.yaml without sending it",
		Long:  `Parses the file as the server would. With -o json or yaml it prints the normalized app.`,
		Flags: func(fs *flag.FlagSet) { fs.StringVar(&file, "f", "", "app `FILE`") },
		Run: func(c *cli.Context, args []string) error {
			if len(args) != 0 {
				return cli.Usagef("check takes no arguments; give the file with -f")
			}
			raw, err := composeDocument(file)
			if err != nil {
				return err
			}
			app, err := deployment.ParseApp(raw)
			if err != nil {
				return err
			}
			normalized, err := app.Canonical()
			if err != nil {
				return err
			}
			var v any
			if err = json.Unmarshal(normalized, &v); err != nil {
				return err
			}
			if g.output.Format() != cli.Table {
				return cli.Print(c.Out, g.output.Format(), v, nil)
			}
			fmt.Fprintf(c.Out, "%s: %d service(s), %d volume(s), %d network(s), %d secret(s). OK.\n", app.Name, len(app.Services), len(app.Volumes), len(app.Networks), len(app.Secrets))
			return nil
		},
	}
}

func appDiffCommand(g *globals) *cli.Command {
	var file, save string
	return &cli.Command{
		Name:  "diff",
		Short: "Show what deploying app.yaml would change",
		Long: `Asks the server to plan the file and lists the changes. --save PLAN also
keeps the frozen plan, which 'app deploy --plan PLAN' deploys exactly.`,
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&file, "f", "", "app `FILE`")
			fs.StringVar(&save, "save", "", "save the plan to `PLAN` for deploy --plan")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 0 {
				return cli.Usagef("diff takes no arguments; give the file with -f")
			}
			ctx, cancel := g.Deadline(c)
			defer cancel()
			fileArgs := []string{}
			if file != "" {
				fileArgs = append(fileArgs, "-f", file)
			}
			var d control.AppDiff
			if err := g.composeJSON(ctx, c, s, &d, append([]string{"diff"}, fileArgs...)...); err != nil {
				return err
			}
			warnAutomationRoutes(c, d.IgnoredAutomationRoutes)
			if save != "" {
				if err := g.composeJSON(ctx, c, s, nil, append([]string{"plan", "--out", save}, fileArgs...)...); err != nil {
					return err
				}
				fmt.Fprintf(c.Err, "Saved the plan to %s. Deploy it with 'mydc app deploy --plan %s'.\n", save, save)
			}
			return cli.Print(c.Out, g.output.Format(), d, func() cli.Rows {
				t := cli.Rows{Header: []string{"object", "change", "reason"}}
				for _, ch := range d.Changes {
					t.Add(ch.Key, strings.ToLower(ch.Action), ch.Reason)
				}
				return t
			})
		}),
	}
}

// appWait is --no-wait (follow.go) plus how long deploy and down wait.
type appWait struct {
	waitFlags
	limit time.Duration
}

func (w *appWait) register(fs *flag.FlagSet) {
	w.waitFlags.register(fs)
	fs.DurationVar(&w.limit, "wait-timeout", 15*time.Minute, "stop waiting after this long (the change goes on)")
}

func (w *appWait) context(c *cli.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(c.Ctx, w.limit)
}

// appName reads the app name from FILE or a saved plan.
func appName(file, plan string) (string, error) {
	if plan != "" {
		raw, err := composeDocument(plan)
		if err != nil {
			return "", err
		}
		p, err := deployment.DecodeBlueprint(bytes.TrimSpace(raw))
		if err != nil {
			return "", fmt.Errorf("%s: %w", plan, err)
		}
		return p.Scope().App, nil
	}
	raw, err := composeDocument(file)
	if err != nil {
		return "", err
	}
	app, err := deployment.ParseApp(raw)
	if err != nil {
		return "", err
	}
	return app.Name, nil
}

func appDeployCommand(g *globals) *cli.Command {
	var file, plan string
	var id cli.IDFlag
	var wait appWait
	var passwords groupPasswordFDs
	return &cli.Command{
		Name:  "deploy",
		Short: "Deploy app.yaml (create or update the app) and wait until it is healthy",
		Long: `Plans the file on the server, uploads it and starts the deployment, then
waits until every service is healthy. --plan PLAN deploys a plan saved by
'app diff --save'. Groups that must approve are asked for their password on
the terminal, or read from --group-password-fd in scripts. If the command
stops part way, 'mydc op resume ID' continues the same deployment.`,
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&file, "f", "", "app `FILE`")
			fs.Var(&passwords, "group-password-fd", "for scripts: read the password of `REALM/GROUP=FD` (cluster: /GROUP) from that open file descriptor (repeat)")
			fs.StringVar(&plan, "plan", "", "deploy this saved `PLAN` instead of a file")
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			wait.register(fs)
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 0 || file != "" && plan != "" {
				return cli.Usagef("deploy takes -f FILE or --plan PLAN and no arguments")
			}
			name, err := appName(file, plan)
			if err != nil {
				return err
			}
			op := id.Get()
			if err = g.Record(s, "app-deploy", "app deploy "+name, op); err != nil {
				return err
			}
			fmt.Fprintf(c.Err, "Operation %s\n", op)
			flow := []string{"up", "--operation", op}
			if plan != "" {
				flow = append(flow, "--plan", plan)
			} else if file != "" {
				flow = append(flow, "-f", file)
			}
			for _, name := range slices.Sorted(maps.Keys(passwords.values)) {
				flow = append(flow, "--group-password-fd", fmt.Sprintf("%s=%d", name, passwords.values[name]))
			}
			if g.noInput {
				flow = append(flow, "--no-input")
			}
			warnAutomationRoutes(c, automationRoutes(file, plan))
			ctx, cancel := g.Deadline(c)
			var reply struct {
				Status string        `json:"status"`
				App    string        `json:"app"`
				Phase  string        `json:"phase"`
				Result *state.Result `json:"result"`
			}
			err = g.composeJSON(ctx, c, s, &reply, flow...)
			cancel()
			if err != nil && reply.Status == "rejected" && reply.Result != nil {
				// The flow's reply goes to a buffer; say which step the server refused.
				_, detail := changeState(*reply.Result, false)
				fmt.Fprintf(c.Err, "the server refused the %s step: %s\n", reply.Phase, detail)
			}
			if err == nil && reply.Status == "accepted" && !wait.noWait {
				fmt.Fprintf(c.Err, "Deploying %s. Waiting until it is healthy (Ctrl-C stops waiting, not the deployment).\n", reply.App)
				wctx, wcancel := wait.context(c)
				err = g.composeJSON(wctx, c, s, nil, "wait", "--operation", op, "-p", reply.App)
				wcancel()
			}
			return g.finishAppOp(c, s, cli.Op{ID: op, Kind: "app-deploy"}, err)
		}),
	}
}

func appDownCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var wait appWait
	return &cli.Command{
		Name:  "down",
		Args:  "APP",
		Short: "Take an app down: stop and remove its containers",
		Long: `Volumes and secrets stay as their own settings say. The app's history is
kept until the server rotates it. Waits until every container is removed.`,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			wait.register(fs)
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 1 {
				return cli.Usagef("down needs one app name")
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			fmt.Fprintf(c.Err, "This stops and removes every container of %s in %s.\n", args[0], tenant)
			if err = g.Prompter(c).Confirm("Take it down?"); err != nil {
				return err
			}
			op := id.Get()
			if err = g.Record(s, "app-down", "app down "+args[0], op); err != nil {
				return err
			}
			fmt.Fprintf(c.Err, "Operation %s\n", op)
			ctx, cancel := g.Deadline(c)
			err = g.composeJSON(ctx, c, s, nil, "down", "--operation", op, "-p", args[0])
			cancel()
			if err == nil && !wait.noWait {
				fmt.Fprintf(c.Err, "Taking %s down. Waiting until its containers are removed.\n", args[0])
				wctx, wcancel := wait.context(c)
				err = g.composeJSON(wctx, c, s, nil, "wait", "--operation", op, "-p", args[0], "--condition", "retired")
				wcancel()
			}
			return g.finishAppOp(c, s, cli.Op{ID: op, Kind: "app-down"}, err)
		}),
	}
}

// finishAppOp settles a deploy or down in the op index from what the server
// says now, prints it, and returns the flow's error (or a failed result).
func (g *globals) finishAppOp(c *cli.Context, s *session, op cli.Op, flowErr error) error {
	ctx, cancel := g.Deadline(c)
	defer cancel()
	st, detail, err := appOpState(ctx, g, s, op)
	if err != nil {
		if flowErr != nil {
			return flowErr
		}
		return err
	}
	g.settle(op.ID, st, detail)
	if perr := cli.Print(c.Out, g.output.Format(), map[string]any{"id": op.ID, "state": st, "detail": detail}, func() cli.Rows {
		t := cli.Rows{Header: []string{"id", "state", "detail"}}
		t.Add(op.ID, st, detail)
		return t
	}); perr != nil {
		return perr
	}
	switch {
	case flowErr != nil:
		var exit cli.ExitError
		if errors.As(flowErr, &exit) && exit.Code == exitUnknown && st != cli.Failed {
			return cli.ExitError{Code: exitUnknown, Err: fmt.Errorf("not finished yet; 'mydc op show %s' checks it and 'mydc op resume %s' continues it", op.ID, op.ID)}
		}
		return flowErr
	case st == cli.Failed:
		return cli.ExitError{Code: 1}
	}
	return nil
}

// appOpState reads what became of an app deploy or down with its ID.
func appOpState(ctx context.Context, g *globals, s *session, op cli.Op) (cli.State, string, error) {
	tenant, err := g.Tenant(s, true)
	if err != nil {
		return "", "", err
	}
	if op.Kind == "app-down" {
		return appDownState(ctx, s, tenant, op.ID)
	}
	intent, err := userauth.LoadCompose(s.Home, s.Client, s.Stored.Session, op.ID)
	if errors.Is(err, userauth.ErrOperationMissing) {
		if _, serr := userauth.LoadComposeSources(s.Home, s.Client, s.Stored.Session, op.ID); serr == nil {
			return cli.Sending, "waiting for its sources; 'mydc op resume' continues it", nil
		}
		return cli.Failed, "not sent", nil
	}
	if err != nil {
		return "", "", err
	}
	reply, err := s.Client.AppOperation(ctx, s.Target, s.Stored.Session, tenant, control.AppOperationRequest{App: intent.Scope.App, ID: op.ID})
	if err != nil {
		return "", "", err
	}
	view := reply.AppOperation
	if view == nil || !view.Found || view.Operation == nil {
		return cli.Sending, "the server has not started it; 'mydc op resume' continues it", nil
	}
	status := strings.ToLower(view.Operation.Status)
	switch {
	case view.Operation.Failed || view.Operation.Status == "Failed":
		return cli.Failed, intent.Scope.App + " " + status, nil
	case view.Operation.Status == "Succeeded":
		return cli.Done, intent.Scope.App + " deployed", nil
	case !view.Current:
		return cli.Done, intent.Scope.App + " " + status + " (replaced by a later deployment)", nil
	}
	detail := intent.Scope.App + " " + status
	if len(view.Waiting) > 0 {
		detail += "; waiting: " + strings.Join(view.Waiting, "; ")
	}
	if view.Operation.Status == "Planned" {
		detail += plannedHint(ctx, s, tenant)
	}
	return cli.Accepted, detail, nil
}

// plannedHint says why a deploy may still be planned. A server starts no
// container for a tenant whose limit there allows no connections
// (MaxConsumers 0, for example a node-wide limit set without it).
func plannedHint(ctx context.Context, s *session, tenant string) string {
	var consumers, packets []string
	after := ""
	for {
		reply, err := s.Client.ResourcePage(ctx, s.Target, s.Stored.Session, tenant, after)
		if err != nil {
			return ""
		}
		for _, e := range reply.Resources {
			l := e.Limit
			if l == nil || l.Tenant != tenant {
				continue
			}
			if l.MaxConsumers < 1 {
				consumers = append(consumers, l.Node)
			}
			// The leader prepares a TUN step only with room for one packet
			// of the smallest MTU plus its frame (applications.go advanceApps).
			if l.PacketQueuePackets < 1 || l.PacketQueueBytes < 1280+120 {
				packets = append(packets, l.Node)
			}
		}
		if reply.ResourcesNext == "" {
			break
		}
		after = reply.ResourcesNext
	}
	hint := ""
	if len(consumers) > 0 {
		hint += fmt.Sprintf("; waiting: the limit of %s on %s allows no connections (max consumers 0); a system administrator raises it with 'mydc node quota set NODE --consumers N' and 'mydc tenant quota set %s NODE --cpu C --memory M --consumers N'", tenant, strings.Join(consumers, ","), tenant)
	}
	if len(packets) > 0 {
		hint += fmt.Sprintf("; waiting if the app uses a TUN network: the limit of %s on %s has no packet queue; a system administrator sets it with 'mydc tenant quota set %s NODE --cpu C --memory M --packet-queue N --packet-queue-bytes SIZE'", tenant, strings.Join(packets, ","), tenant)
	}
	return hint
}

func appDownState(ctx context.Context, s *session, tenant, id string) (cli.State, string, error) {
	record, err := userauth.LoadOperation(s.Home, s.Client, s.Stored.Session, "compose-down/"+id)
	if errors.Is(err, userauth.ErrOperationMissing) {
		return cli.Failed, "not sent", nil
	}
	if err != nil {
		return "", "", err
	}
	var payload control.AppDown
	if json.Unmarshal(record.Operation.Change.Payload, &payload) != nil {
		return "", "", errors.New("the saved down request is damaged")
	}
	result := record.Result
	if result == nil {
		reply, err := s.Client.Result(ctx, s.Target, s.Stored.Session, record.Operation)
		if err != nil {
			return "", "", err
		}
		if !reply.Found || reply.Result == nil {
			return cli.Sending, "the server has no result for this ID yet; 'mydc op resume' sends it again", nil
		}
		result = reply.Result
	}
	if result.Code != state.Applied {
		st, detail := changeState(*result, false)
		return st, detail, nil
	}
	current, found, err := composeInventory(ctx, s.Client, s.Target, s.Stored, tenant, payload.App)
	if err != nil {
		return "", "", err
	}
	if !found || current.Retirement != nil && current.Retirement.ID == id && current.Retirement.Status == "Retired" {
		return cli.Done, payload.App + " is down", nil
	}
	if current.Retirement == nil || current.Retirement.ID != id {
		return cli.Done, payload.App + " was redeployed after this down", nil
	}
	return cli.Accepted, payload.App + " going down", nil
}

func appOpHandler(g *globals) cli.Handler {
	settle := func(c *cli.Context, op cli.Op, resume bool) (cli.State, string, error) {
		s, err := g.opSession(c, op)
		if err != nil {
			return "", "", err
		}
		defer s.Close()
		ctx, cancel := g.Deadline(c)
		defer cancel()
		if resume {
			flow := []string{"resume", "--operation", op.ID}
			if g.noInput {
				flow = append(flow, "--no-input")
			}
			// The flow prints its reasons; the state below says where it is.
			_ = g.composeFlow(ctx, c, s, io.Discard, flow...)
		}
		return appOpState(ctx, g, s, op)
	}
	return cli.Handler{
		Show:   func(c *cli.Context, op cli.Op) (cli.State, string, error) { return settle(c, op, false) },
		Resume: func(c *cli.Context, op cli.Op) (cli.State, string, error) { return settle(c, op, true) },
	}
}

func appHistoryCommand(g *globals) *cli.Command {
	var after string
	return &cli.Command{
		Name:  "history",
		Args:  "APP",
		Short: "List the app's deployed versions, newest first",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&after, "after", "", "continue after this `CURSOR` from the last page")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 1 {
				return cli.Usagef("history needs one app name")
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			ctx, cancel := g.Deadline(c)
			defer cancel()
			reply, err := s.Client.AppRevisions(ctx, s.Target, s.Stored.Session, tenant, control.AppSourceSelection{App: args[0]}, after)
			if err != nil {
				return err
			}
			rows := reply.AppRevisions
			if rows == nil {
				rows = []control.AppRevisionView{}
			}
			if reply.AppRevisionsNext != "" {
				fmt.Fprintf(c.Err, "More versions: --after %s\n", reply.AppRevisionsNext)
			}
			return cli.Print(c.Out, g.output.Format(), rows, func() cli.Rows {
				t := cli.Rows{Header: []string{"revision", "status", "operation", "by", "source", "completed"}}
				for _, r := range rows {
					done := ""
					if r.CompletedAt > 0 {
						done = time.Unix(int64(r.CompletedAt), 0).Local().Format("2006-01-02 15:04")
					}
					source := r.Source
					if r.Automatic {
						source += " (cd)"
					}
					t.Add(r.Revision, strings.ToLower(r.Status), r.Operation, r.SubmittedBy, source, done)
				}
				return t
			})
		}),
	}
}

func appSourceCommand(g *globals) *cli.Command {
	var revision uint64
	var section string
	return &cli.Command{
		Name:  "source",
		Args:  "APP",
		Short: "Print the app.yaml the server keeps for a version",
		Long:  `Prints the exact file of the latest version, or of --revision N (see 'app history').`,
		Flags: func(fs *flag.FlagSet) {
			fs.Uint64Var(&revision, "revision", 0, "version `N` (default: the latest)")
			fs.StringVar(&section, "section", "", "source (default), local-services, overlays, or pending-local (local services waiting for the next sync)")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 1 {
				return cli.Usagef("source needs one app name")
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			q := control.AppSourceSelection{App: args[0], Revision: revision, Section: section}
			if !q.Valid(false) {
				return cli.Usagef("invalid app name, --revision or --section")
			}
			ctx, cancel := g.Deadline(c)
			defer cancel()
			raw, _, err := s.Client.ReadAppSource(ctx, s.Target, s.Stored.Session, tenant, q)
			if err != nil {
				return err
			}
			_, err = c.Out.Write(raw)
			return err
		}),
	}
}

// forward returns --name=value for each of names given on the command line.
func forward(c *cli.Context, names ...string) []string {
	var out []string
	for _, n := range names {
		if f := c.Flags.Lookup(n); f != nil && c.Set(n) {
			out = append(out, "--"+n+"="+f.Value.String())
		}
	}
	return out
}

func appTarget(args []string, what string) (app, service string, err error) {
	if len(args) != 2 {
		return "", "", cli.Usagef("%s needs APP SERVICE", what)
	}
	return args[0], args[1], nil
}

// streamContext is for a command that runs until the person stops it.
func (g *globals) streamContext() (context.Context, context.CancelFunc) {
	return containerStreamContext(g.timeout)
}

func appLogsCommand(g *globals) *cli.Command {
	var follow bool
	return &cli.Command{
		Name:  "logs",
		Args:  "APP SERVICE",
		Short: "Print a service's container logs",
		Long:  `Prints the last 200 lines. -f keeps printing new lines until Ctrl-C.`,
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&follow, "f", false, "follow new lines")
			fs.String("tail", "", "last `N` lines (at most 10000)")
			fs.String("since", "", "from this RFC3339 `time`")
			fs.String("until", "", "up to this RFC3339 `time`")
			fs.String("cursor", "", "continue from this `CURSOR`")
			fs.Bool("timestamps", false, "show timestamps")
			fs.Bool("stdout", false, "only standard output")
			fs.Bool("stderr", false, "only standard error")
			fs.String("instance", "", "one `TASK` of a service with several")
			fs.String("max-bytes", "", "print at most `N` bytes")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			app, service, err := appTarget(args, "logs")
			if err != nil {
				return err
			}
			flow := append([]string{"logs", "-p", app, service}, forward(c, "tail", "since", "until", "cursor", "timestamps", "stdout", "stderr", "instance", "max-bytes")...)
			if follow {
				flow = append(flow, "--follow")
			}
			return g.containerRead(c, s, follow, flow)
		}),
	}
}

func appSampleCommand(g *globals, name, short string) *cli.Command {
	var watch bool
	return &cli.Command{
		Name:  name,
		Args:  "APP SERVICE",
		Short: short,
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&watch, "watch", false, "repeat until Ctrl-C")
			fs.String("interval", "", "with --watch, sample every `DURATION` (default 2s)")
			fs.String("instance", "", "one `TASK` of a service with several")
			fs.String("max-bytes", "", "print at most `N` bytes")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			app, service, err := appTarget(args, name)
			if err != nil {
				return err
			}
			flow := append([]string{name, "-p", app, service}, forward(c, "interval", "instance", "max-bytes")...)
			if watch {
				flow = append(flow, "--watch")
			}
			return g.containerRead(c, s, watch, flow)
		}),
	}
}

// containerRead runs logs, top or stats. Table output is the container's
// own text; -o json or yaml asks the flow for its structured result.
func (g *globals) containerRead(c *cli.Context, s *session, stream bool, flow []string) error {
	var ctx context.Context
	var cancel context.CancelFunc
	if stream {
		ctx, cancel = g.streamContext()
	} else {
		ctx, cancel = g.Deadline(c)
	}
	defer cancel()
	switch g.output.Format() {
	case cli.JSON:
		return g.composeFlow(ctx, c, s, c.Out, append(flow, "--json")...)
	case cli.YAML:
		if stream {
			return cli.Usagef("-o yaml cannot follow; use -o json")
		}
		var v any
		if err := g.composeJSON(ctx, c, s, &v, append(flow, "--json")...); err != nil {
			return err
		}
		return cli.Print(c.Out, cli.YAML, v, nil)
	}
	return g.composeFlow(ctx, c, s, c.Out, flow...)
}

func appInspectCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "inspect",
		Args:  "APP SERVICE",
		Short: "Show a service's container details and recent lifecycle events",
		Flags: func(fs *flag.FlagSet) {
			fs.String("history", "", "last `N` lifecycle events (default 20, at most 100)")
			fs.String("instance", "", "one `TASK` of a service with several")
			fs.String("max-bytes", "", "print at most `N` bytes")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			app, service, err := appTarget(args, "inspect")
			if err != nil {
				return err
			}
			ctx, cancel := g.Deadline(c)
			defer cancel()
			var v any
			if err = g.composeJSON(ctx, c, s, &v, append([]string{"inspect", "-p", app, service}, forward(c, "history", "instance", "max-bytes")...)...); err != nil {
				return err
			}
			return cli.Print(c.Out, g.output.Format(), v, nil)
		}),
	}
}

func appExecCommand(g *globals) *cli.Command {
	var interactive, tty bool
	var instance string
	var id cli.IDFlag
	return &cli.Command{
		Name:  "exec",
		Args:  "APP SERVICE -- COMMAND [ARG...]",
		Short: "Run a command in a service's container",
		Long: `Runs COMMAND once in the running container. -i passes standard input and
-t gives it a terminal. If the connection drops, the command is not started
again; run exec with the same --id to see what became of it.`,
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&interactive, "i", false, "pass standard input")
			fs.BoolVar(&tty, "t", false, "allocate a terminal")
			fs.StringVar(&instance, "instance", "", "one `TASK` of a service with several")
			fs.Var(&id, "id", "exec `ID` (default: a new one)")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			app, service, err := appTarget(args, "exec")
			if err != nil {
				return err
			}
			if len(c.Rest) == 0 {
				return cli.Usagef("exec needs a command after --")
			}
			op := id.Get()
			flow := []string{"exec", "-p", app, "--operation", op}
			if interactive {
				flow = append(flow, "-i")
			}
			if tty {
				flow = append(flow, "-t")
			}
			if instance != "" {
				flow = append(flow, "--instance", instance)
			}
			flow = append(append(flow, service, "--"), c.Rest...)
			ctx, cancel := g.streamContext()
			defer cancel()
			return g.composeFlow(ctx, c, s, c.Out, flow...)
		}),
	}
}

// restartLike is restart or clear-logs: both act on one service's
// containers, are confirmed first and are settled with 'mydc op'.
type restartLike struct {
	name, short, long, kind, warning string
	flow                             func(app, service, op string) []string
	status                           func(app, op string) []string
}

var appRestart = restartLike{
	name:    "restart",
	short:   "Restart a service's containers",
	long:    `Restarts the running containers of SERVICE in place. Logs and the writable layer are kept.`,
	kind:    "app-restart",
	warning: "This restarts the containers of %s in %s; they stop serving while they restart.",
	flow: func(app, service, op string) []string {
		return []string{"restart", "-p", app, "--operation", op, service}
	},
	status: func(app, op string) []string { return []string{"restart-status", "-p", app, "--operation", op} },
}

var appClearLogs = restartLike{
	name:    "clear-logs",
	short:   "Clear a service's container logs by recreating its containers",
	long:    `Recreates the containers of SERVICE (and stops what depends on them meanwhile). Local logs and the writable layer are lost for good; volume data and logs copied elsewhere are kept.`,
	kind:    "app-clear-logs",
	warning: "This recreates the containers of %s in %s. Their local logs and writable layer are lost for good; volume data is kept.",
	flow: func(app, service, op string) []string {
		return []string{"logs-clear", "-p", app, "--recreate", "--operation", op, service}
	},
	status: func(app, op string) []string { return []string{"logs-clear-status", "-p", app, "--operation", op} },
}

func appRestartCommand(g *globals) *cli.Command   { return appRestartLike(g, appRestart) }
func appClearLogsCommand(g *globals) *cli.Command { return appRestartLike(g, appClearLogs) }

func appRestartLike(g *globals, r restartLike) *cli.Command {
	var instance string
	var id cli.IDFlag
	return &cli.Command{
		Name:  r.name,
		Args:  "APP SERVICE",
		Short: r.short,
		Long:  r.long,
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&instance, "instance", "", "only this `TASK` of the service")
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			app, service, err := appTarget(args, r.name)
			if err != nil {
				return err
			}
			target := service
			if instance != "" {
				target += " (" + instance + ")"
			}
			fmt.Fprintf(c.Err, r.warning+"\n", target, app)
			if err = g.Prompter(c).Confirm("Go ahead?"); err != nil {
				return err
			}
			op := id.Get()
			summary := "app " + r.name + " " + app + " " + service
			if instance != "" {
				summary += " --instance " + instance
			}
			if err = g.Record(s, r.kind, summary, op); err != nil {
				return err
			}
			fmt.Fprintf(c.Err, "Operation %s\n", op)
			flow := r.flow(app, service, op)
			if instance != "" {
				flow = append(flow[:len(flow)-1], "--instance", instance, service)
			}
			ctx, cancel := g.Deadline(c)
			defer cancel()
			var reply struct {
				Status    string `json:"status"`
				Execution struct{ Status string }
			}
			flowErr := g.composeJSON(ctx, c, s, &reply, flow...)
			st, detail := restartState(reply.Status, reply.Execution.Status)
			if flowErr != nil {
				var exit cli.ExitError
				if errors.As(flowErr, &exit) && exit.Code == exitUnknown {
					st, detail = cli.Sending, "unknown; 'mydc op show' checks it"
				} else if reply.Status == "" {
					st, detail = cli.Failed, "not sent"
				}
			}
			g.settle(op, st, detail)
			if err := cli.Print(c.Out, g.output.Format(), map[string]any{"id": op, "state": st, "detail": detail}, func() cli.Rows {
				t := cli.Rows{Header: []string{"id", "state", "detail"}}
				t.Add(op, st, detail)
				return t
			}); err != nil {
				return err
			}
			return flowErr
		}),
	}
}

// restartState maps a restart or log-clear reply and execution status to
// the op index.
func restartState(reply, execution string) (cli.State, string) {
	switch reply {
	case "Rejected":
		return cli.Failed, "rejected"
	case "Unknown", "":
		return cli.Sending, "unknown; 'mydc op show' checks it"
	}
	e := strings.ToLower(execution)
	switch {
	case e == "succeeded" || e == "completed" || e == "done":
		return cli.Done, e
	case strings.Contains(e, "fail"):
		return cli.Failed, e
	case e == "":
		return cli.Accepted, "accepted"
	}
	return cli.Accepted, e
}

// restartOpHandler settles restart and clear-logs. The app, service and
// task come from the op's summary, which this file wrote.
func restartOpHandler(g *globals, r restartLike) cli.Handler {
	settle := func(c *cli.Context, op cli.Op, resume bool) (cli.State, string, error) {
		words := strings.Fields(op.Summary)
		if len(words) < 4 || words[0] != "app" || words[1] != r.name {
			return "", "", fmt.Errorf("operation %s is not an app %s", op.ID, r.name)
		}
		app, service := words[2], words[3]
		s, err := g.opSession(c, op)
		if err != nil {
			return "", "", err
		}
		defer s.Close()
		ctx, cancel := g.Deadline(c)
		defer cancel()
		if resume {
			flow := r.flow(app, service, op.ID)
			if len(words) == 6 && words[4] == "--instance" {
				flow = append(flow[:len(flow)-1], "--instance", words[5], service)
			}
			var reply struct {
				Status    string `json:"status"`
				Execution struct{ Status string }
			}
			if err := g.composeJSON(ctx, c, s, &reply, flow...); err != nil {
				return cli.Sending, "unknown; 'mydc op show' checks it", nil
			}
			st, detail := restartState(reply.Status, reply.Execution.Status)
			return st, detail, nil
		}
		var status struct{ Status string }
		var buf bytes.Buffer
		if err := g.composeFlow(ctx, c, s, &buf, r.status(app, op.ID)...); err != nil {
			return "", "", err
		}
		if strings.TrimSpace(buf.String()) == "null" {
			return cli.Sending, "the server has no record of it; 'mydc op resume' sends it again", nil
		}
		if json.Unmarshal(buf.Bytes(), &status) != nil {
			return "", "", errors.New("unexpected status reply")
		}
		st, detail := restartState("Accepted", status.Status)
		return st, detail, nil
	}
	return cli.Handler{
		Show:   func(c *cli.Context, op cli.Op) (cli.State, string, error) { return settle(c, op, false) },
		Resume: func(c *cli.Context, op cli.Op) (cli.State, string, error) { return settle(c, op, true) },
	}
}

func init() {
	opKinds["app-deploy"] = appOpHandler
	opKinds["app-down"] = appOpHandler
	opKinds["app-restart"] = func(g *globals) cli.Handler { return restartOpHandler(g, appRestart) }
	opKinds["app-clear-logs"] = func(g *globals) cli.Handler { return restartOpHandler(g, appClearLogs) }
}

// warnAutomationRoutes says which ingress routes certificate automation
// overrides. Deploy goes on: the path keeps working for hosts outside
// registered domains and for HTTPS.
func warnAutomationRoutes(c *cli.Context, routes []string) {
	for _, r := range routes {
		fmt.Fprintf(c.Err, "warning: ingress route %s is ignored for plain HTTP on registered-domain hosts: certificate automation uses %s\n", r, ingress.ACMEChallengePath)
	}
}

// automationRoutes reads AutomationPathRoutes from FILE or a saved plan; a
// file that does not parse is left for the server to report.
func automationRoutes(file, plan string) []string {
	path := file
	if plan != "" {
		path = plan
	}
	raw, err := composeDocument(path)
	if err != nil {
		return nil
	}
	if plan != "" {
		p, err := deployment.DecodeBlueprint(bytes.TrimSpace(raw))
		if err != nil {
			return nil
		}
		return p.AutomationPathRoutes()
	}
	app, err := deployment.ParseApp(raw)
	if err != nil || app.MyDC.Ingress == nil {
		return nil
	}
	return deployment.AutomationPathRoutes(*app.MyDC.Ingress)
}
