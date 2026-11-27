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

	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/cliprofile"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/userauth"
)

// The standalone commands: one container from a one-service app.yaml,
// owned by the tenant and kept out of apps and CD. run, logs, exec, attach
// use the flows of standalone.go (plan, upload, approvals,
// container streams); the other changes are signed here with g.send.

func standaloneCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "standalone",
		Short: "Run single containers outside apps (temporary or kept)",
		Long: `A standalone is one container from an app.yaml with one service. It belongs
to the tenant, not to an app, and CD never touches it. A temporary one
(the default) is removed when its time runs out (1h unless --ttl says
otherwise, at most 24h from creation) or after nobody has been attached for
--grace; 'keep' makes it permanent.`,
		Sub: []*cli.Command{
			standaloneRunCommand(g),
			standaloneListCommand(g),
			standaloneShowCommand(g),
			standaloneControlCommand(g, "stop", "Stop a standalone's container (it is kept)"),
			standaloneControlCommand(g, "start", "Start a stopped standalone's container"),
			standaloneControlCommand(g, "restart", "Restart a standalone's container in place"),
			standaloneRemoveCommand(g),
			standaloneKeepCommand(g),
			standaloneExtendCommand(g),
			standaloneLogsCommand(g),
			standaloneSampleCommand(g, "top", "Show the processes of a standalone's container"),
			standaloneSampleCommand(g, "stats", "Show a standalone's container resource use"),
			standaloneInspectCommand(g),
			standaloneExecCommand(g),
			standaloneAttachCommand(g),
			standaloneClearLogsCommand(g),
		},
	}
}

// standaloneFlow runs one flow of standalone.go in the session's tenant.
// Its JSON goes to out and its reasons to c.Err; a non-zero exit becomes
// cli.ExitError with the same code (4: the outcome is not known yet).
func (g *globals) standaloneFlow(ctx context.Context, c *cli.Context, s *session, out io.Writer, args ...string) error {
	tenant, err := g.Tenant(s, true)
	if err != nil {
		return err
	}
	args = append([]string{args[0], "--tenant", tenant}, args[1:]...)
	if code := runStandalone(ctx, args, s.Client, s.Target, s.Stored, s.Home, cliprofile.Selection{}, out, c.Err); code != 0 {
		return cli.ExitError{Code: code}
	}
	return nil
}

func (g *globals) standaloneJSON(ctx context.Context, c *cli.Context, s *session, v any, args ...string) error {
	var buf bytes.Buffer
	err := g.standaloneFlow(ctx, c, s, &buf, args...)
	if v != nil && buf.Len() != 0 {
		if e := json.Unmarshal(buf.Bytes(), v); e != nil && err == nil {
			return errors.New("unexpected reply from the standalone flow")
		}
	}
	return err
}

func standaloneName(args []string, what string, extra int) (string, error) {
	if len(args) != 1+extra || !lifecycle.ValidID(args[0]) {
		if extra == 1 {
			return "", cli.Usagef("%s needs NAME and one more argument", what)
		}
		return "", cli.Usagef("%s needs one standalone NAME", what)
	}
	return args[0], nil
}

// wholeSeconds turns a --ttl/--grace duration into the server's seconds.
func wholeSeconds(name string, d time.Duration) (int64, error) {
	if d < 0 || d%time.Second != 0 || d > 24*time.Hour {
		return 0, cli.Usagef("--%s must be whole seconds up to 24h, such as 30m", name)
	}
	return int64(d / time.Second), nil
}

func standaloneRunCommand(g *globals) *cli.Command {
	var file, node, lifetime, mode, restart string
	var ttl, grace time.Duration
	var dryRun bool
	var id cli.IDFlag
	var passwords groupPasswordFDs
	return &cli.Command{
		Name:  "run",
		Args:  "NAME",
		Short: "Start a standalone from an app.yaml with one service",
		Long: `Plans FILE on the server, uploads it and starts the container. --dry-run
prints the plan and sends nothing. Groups that must approve are asked for
their password on the terminal, or read from --group-password-fd in
scripts. Running it again with the same --id continues the same start
('sfcli op resume ID' does the same).`,
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&file, "f", "", "app.yaml `FILE` with one service")
			fs.StringVar(&node, "node", "", "run on this `server`")
			fs.StringVar(&lifetime, "lifetime", "", "temp (default) or fixed")
			fs.StringVar(&mode, "mode", "", "entrypoint (default) or shell (an interactive shell for attach)")
			fs.DurationVar(&ttl, "ttl", 0, "temp: remove after this `long` (default 1h, at most 24h)")
			fs.DurationVar(&grace, "grace", 0, "temp: remove after nobody is attached for this `long` (default 10m)")
			fs.StringVar(&restart, "restart", "", "fixed: no, on-failure or always")
			fs.BoolVar(&dryRun, "dry-run", false, "only print the plan")
			fs.Var(&passwords, "group-password-fd", "for scripts: read the password of `REALM/GROUP=FD` (cluster: /GROUP) from that open file descriptor (repeat)")
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			name, err := standaloneName(args, "run", 0)
			if err != nil {
				return err
			}
			ttlSeconds, err := wholeSeconds("ttl", ttl)
			if err != nil {
				return err
			}
			graceSeconds, err := wholeSeconds("grace", grace)
			if err != nil {
				return err
			}
			op := id.Get()
			_, loadErr := userauth.LoadCompose(s.Home, s.Client, s.Stored.Session, op)
			resume := loadErr == nil && !dryRun
			if !resume && file == "" {
				return cli.Usagef("run needs -f FILE")
			}
			var flow []string
			switch {
			case dryRun:
				flow = []string{"plan", name}
			case resume:
				flow = []string{"resume", name, "--operation", op}
			default:
				flow = []string{"up", name, "--operation", op}
			}
			if !resume {
				flow = append(flow, "-f", file)
				for _, o := range [][2]string{{"node", node}, {"lifetime", lifetime}, {"mode", mode}, {"restart", restart}} {
					if o[1] != "" {
						flow = append(flow, "--"+o[0], o[1])
					}
				}
				if ttlSeconds != 0 {
					flow = append(flow, "--ttl-seconds", fmt.Sprint(ttlSeconds))
				}
				if graceSeconds != 0 {
					flow = append(flow, "--grace-seconds", fmt.Sprint(graceSeconds))
				}
			}
			if dryRun {
				ctx, cancel := g.Deadline(c)
				defer cancel()
				var plan any
				if err := g.standaloneJSON(ctx, c, s, &plan, flow...); err != nil {
					return err
				}
				return cli.Print(c.Out, g.output.Format(), plan, nil)
			}
			for _, group := range slices.Sorted(maps.Keys(passwords.values)) {
				flow = append(flow, "--group-password-fd", fmt.Sprintf("%s=%d", group, passwords.values[group]))
			}
			if g.noInput {
				flow = append(flow, "--no-input")
			}
			if err = g.Record(s, "standalone-run", "standalone run "+name, op); err != nil {
				return err
			}
			fmt.Fprintf(c.Err, "Operation %s\n", op)
			ctx, cancel := g.Deadline(c)
			flowErr := g.standaloneFlow(ctx, c, s, io.Discard, flow...)
			cancel()
			return g.finishStandaloneRun(c, s, cli.Op{ID: op, Kind: "standalone-run", Summary: "standalone run " + name}, flowErr)
		}),
	}
}

// finishStandaloneRun settles a run in the op index from what the server
// says now, prints it and returns the flow's error (or a failed result).
func (g *globals) finishStandaloneRun(c *cli.Context, s *session, op cli.Op, flowErr error) error {
	ctx, cancel := g.Deadline(c)
	defer cancel()
	st, detail, err := standaloneRunState(ctx, g, s, op)
	if err != nil {
		if flowErr != nil {
			return flowErr
		}
		return err
	}
	g.settle(op.ID, st, detail)
	if err := printOpLine(c, g, op.ID, st, detail); err != nil {
		return err
	}
	switch {
	case flowErr != nil:
		var exit cli.ExitError
		if errors.As(flowErr, &exit) && exit.Code == exitUnknown && st != cli.Failed {
			return cli.ExitError{Code: exitUnknown, Err: fmt.Errorf("not finished yet; 'sfcli op show %s' checks it and 'sfcli op resume %s' continues it", op.ID, op.ID)}
		}
		return flowErr
	case st == cli.Failed:
		return cli.ExitError{Code: 1}
	}
	return nil
}

func printOpLine(c *cli.Context, g *globals, id string, st cli.State, detail string) error {
	return cli.Print(c.Out, g.output.Format(), map[string]any{"id": id, "state": st, "detail": detail}, func() cli.Rows {
		t := cli.Rows{Header: []string{"id", "state", "detail"}}
		t.Add(id, st, detail)
		return t
	})
}

// standaloneRunState reads what became of a run with its ID. The name is
// the third word of the summary this file wrote.
func standaloneRunState(ctx context.Context, g *globals, s *session, op cli.Op) (cli.State, string, error) {
	words := strings.Fields(op.Summary)
	if len(words) != 3 || words[0] != "standalone" || words[1] != "run" {
		return "", "", fmt.Errorf("operation %s is not a standalone run", op.ID)
	}
	name := words[2]
	tenant, err := g.Tenant(s, true)
	if err != nil {
		return "", "", err
	}
	if _, err := userauth.LoadCompose(s.Home, s.Client, s.Stored.Session, op.ID); errors.Is(err, userauth.ErrOperationMissing) {
		return cli.Failed, "not sent", nil
	} else if err != nil {
		return "", "", err
	}
	reply, err := s.Client.AppOperation(ctx, s.Target, s.Stored.Session, tenant, control.AppOperationRequest{Standalone: name, ID: op.ID})
	if err != nil {
		return "", "", err
	}
	view := reply.AppOperation
	if view == nil || !view.Found || view.Operation == nil {
		return cli.Sending, "the server has not started it; 'sfcli op resume' continues it", nil
	}
	status := strings.ToLower(view.Operation.Status)
	switch {
	case view.Operation.Failed || view.Operation.Status == "Failed":
		return cli.Failed, name + " " + status, nil
	case view.Operation.Status == "Succeeded":
		return cli.Done, name + " running", nil
	case !view.Current:
		return cli.Done, name + " " + status + " (replaced later)", nil
	}
	detail := name + " " + status
	if len(view.Waiting) > 0 {
		detail += "; waiting: " + strings.Join(view.Waiting, "; ")
	}
	return cli.Accepted, detail, nil
}

func standaloneRunHandler(g *globals) cli.Handler {
	settle := func(c *cli.Context, op cli.Op, resume bool) (cli.State, string, error) {
		s, err := g.opSession(c, op)
		if err != nil {
			return "", "", err
		}
		defer s.Close()
		ctx, cancel := g.Deadline(c)
		defer cancel()
		if resume {
			words := strings.Fields(op.Summary)
			if len(words) == 3 {
				flow := []string{"resume", words[2], "--operation", op.ID}
				if g.noInput {
					flow = append(flow, "--no-input")
				}
				// The flow's own failure is read back from the server below.
				_ = g.standaloneFlow(ctx, c, s, io.Discard, flow...)
			}
		}
		return standaloneRunState(ctx, g, s, op)
	}
	return cli.Handler{
		Show:   func(c *cli.Context, op cli.Op) (cli.State, string, error) { return settle(c, op, false) },
		Resume: func(c *cli.Context, op cli.Op) (cli.State, string, error) { return settle(c, op, true) },
	}
}

// standalonePage reads one standalone (name) or every page of the list.
func standalonePage(ctx context.Context, s *session, tenant, name string) ([]control.StandaloneView, uint64, error) {
	var all []control.StandaloneView
	var epoch uint64
	for after := ""; ; {
		reply, err := s.Client.StandalonePage(ctx, s.Target, s.Stored.Session, tenant, name, after)
		if err != nil {
			return nil, 0, err
		}
		all = append(all, reply.Standalones...)
		epoch = reply.ModuleEpoch
		if name != "" || reply.StandaloneNext == "" || reply.StandaloneNext == after {
			return all, epoch, nil
		}
		after = reply.StandaloneNext
	}
}

// standaloneOne is the current view of NAME.
func (g *globals) standaloneOne(c *cli.Context, s *session, name string) (string, control.StandaloneView, uint64, error) {
	tenant, err := g.Tenant(s, true)
	if err != nil {
		return "", control.StandaloneView{}, 0, err
	}
	ctx, cancel := g.Deadline(c)
	defer cancel()
	views, epoch, err := standalonePage(ctx, s, tenant, name)
	if err != nil {
		return "", control.StandaloneView{}, 0, err
	}
	if len(views) != 1 {
		return "", control.StandaloneView{}, 0, cli.ExitError{Code: 3, Err: fmt.Errorf("standalone %s not found in tenant %s", name, tenant)}
	}
	if views[0].Target == ([32]byte{}) {
		return "", control.StandaloneView{}, 0, cli.ExitError{Code: 3, Err: fmt.Errorf("standalone %s cannot be changed now (no current deployment)", name)}
	}
	return tenant, views[0], epoch, nil
}

func standaloneStatus(v control.StandaloneView) string {
	if v.Metadata.Cleanup != nil {
		return "removing"
	}
	status := strings.ToLower(v.Workload.Operation.Status)
	if v.Metadata.Desired != "" && v.Metadata.Desired != "running" {
		return v.Metadata.Desired
	}
	if status == "" {
		return v.Metadata.Desired
	}
	return status
}

func standaloneLeft(v control.StandaloneView) string {
	if v.Metadata.Lifetime != "temp" {
		return "-"
	}
	return (time.Duration(v.RemainingSeconds) * time.Second).String()
}

func standaloneListCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "list",
		Short: "List the tenant's standalones",
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 0 {
				return cli.Usagef("list takes no arguments")
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			ctx, cancel := g.Deadline(c)
			defer cancel()
			views, _, err := standalonePage(ctx, s, tenant, "")
			if err != nil {
				return err
			}
			if views == nil {
				views = []control.StandaloneView{}
			}
			return cli.Print(c.Out, g.output.Format(), views, func() cli.Rows {
				t := cli.Rows{Header: []string{"name", "lifetime", "status", "node", "left", "creator"}}
				for _, v := range views {
					t.Add(v.Metadata.Name, v.Metadata.Lifetime, standaloneStatus(v), v.Metadata.Node, standaloneLeft(v), v.Metadata.Creator)
				}
				return t
			})
		}),
	}
}

func standaloneShowCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "show",
		Args:  "NAME",
		Short: "Show one standalone with its app.yaml",
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			name, err := standaloneName(args, "show", 0)
			if err != nil {
				return err
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			ctx, cancel := g.Deadline(c)
			defer cancel()
			views, _, err := standalonePage(ctx, s, tenant, name)
			if err != nil {
				return err
			}
			if len(views) != 1 {
				return cli.ExitError{Code: 3, Err: fmt.Errorf("standalone %s not found in tenant %s", name, tenant)}
			}
			v := views[0]
			if v.Definition != nil {
				body, _, err := s.Client.ReadAppSource(ctx, s.Target, s.Stored.Session, tenant, control.AppSourceSelection{Standalone: name})
				if err != nil {
					return err
				}
				v.Definition.Body = body
			}
			return cli.Print(c.Out, g.output.Format(), v, func() cli.Rows {
				m := v.Metadata
				t := cli.Rows{Header: []string{"field", "value"}}
				t.Add("name", m.Name)
				t.Add("lifetime", m.Lifetime)
				t.Add("status", standaloneStatus(v))
				t.Add("mode", m.Mode)
				t.Add("restart", m.Restart)
				t.Add("node", m.Node)
				t.Add("creator", m.Creator)
				t.Add("created", time.Unix(m.CreatedAt, 0).UTC().Format(time.RFC3339))
				if m.Lifetime == "temp" {
					t.Add("expires", time.Unix(m.ExpiresAt, 0).UTC().Format(time.RFC3339))
					t.Add("left", standaloneLeft(v))
					t.Add("attached", m.Connections)
				}
				t.Add("revision", m.Revision)
				return t
			})
		}),
	}
}

func standaloneControlCommand(g *globals, verb, short string) *cli.Command {
	var instance string
	var dryRun bool
	var id cli.IDFlag
	return &cli.Command{
		Name:  verb,
		Args:  "NAME",
		Short: short,
		Long:  short + ". The server accepts it and the node does it; 'sfcli op show ID' follows it.",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&instance, "instance", "", "only this `TASK`")
			fs.BoolVar(&dryRun, "dry-run", false, "only show the plan")
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			name, err := standaloneName(args, verb, 0)
			if err != nil {
				return err
			}
			if done, err := g.savedChange(c, s, id.String(), "standalone "+verb+" "+name, "standalone-"+verb); done {
				return err
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			q := control.TaskRestartQuery{Action: "standalone-" + verb, Selection: containerops.Selection{Standalone: name, Instance: instance}}
			ctx, cancel := g.Deadline(c)
			reply, err := s.Client.QueryTaskRestart(ctx, s.Target, s.Stored.Session, tenant, true, q)
			cancel()
			if err != nil {
				return err
			}
			p := reply.TaskRestartPlan
			if dryRun {
				return cli.Print(c.Out, g.output.Format(), p, nil)
			}
			op := id.Get()
			ch := control.TaskRestartChange{Tenant: tenant, Standalone: name, Operation: op, Target: p.Target, ManagementTarget: p.ManagementTarget}
			ch.Selection.Service = p.Container.Service
			ch.Selection.Instance = p.Container.Instance
			impact := fmt.Sprintf("%s standalone %s (container %s).", strings.ToUpper(verb[:1])+verb[1:], name, p.Container.Instance)
			_, err = g.confirmSend(c, s, impact, change{Kind: "standalone-control", ID: op, Summary: "standalone " + verb + " " + name, Action: q.Action, Expected: p.StandaloneRevision, Epoch: reply.ModuleEpoch, Payload: ch, Async: true})
			if err != nil {
				return err
			}
			return printOpLine(c, g, op, cli.Accepted, "accepted; 'sfcli op show "+op+"' follows it")
		}),
	}
}

// standaloneControlHandler settles stop/start/restart: the change itself,
// then the node's progress once the server accepted it.
func standaloneControlHandler(g *globals) cli.Handler {
	base := changeHandler(g, nil, true)
	follow := func(c *cli.Context, op cli.Op, st cli.State, detail string) (cli.State, string, error) {
		words := strings.Fields(op.Summary)
		if st != cli.Accepted || len(words) != 3 {
			return st, detail, nil
		}
		s, err := g.opSession(c, op)
		if err != nil {
			return "", "", err
		}
		defer s.Close()
		tenant, err := g.Tenant(s, true)
		if err != nil {
			return "", "", err
		}
		ctx, cancel := g.Deadline(c)
		defer cancel()
		reply, err := s.Client.QueryTaskRestart(ctx, s.Target, s.Stored.Session, tenant, false, control.TaskRestartQuery{Operation: op.ID, Selection: containerops.Selection{Standalone: words[2]}})
		if err != nil {
			return "", "", err
		}
		if reply.TaskRestartStatus == nil {
			return st, detail, nil
		}
		st, detail = restartState("Accepted", reply.TaskRestartStatus.Status)
		return st, detail, nil
	}
	return cli.Handler{
		Show: func(c *cli.Context, op cli.Op) (cli.State, string, error) {
			st, detail, err := base.Show(c, op)
			if err != nil {
				return st, detail, err
			}
			return follow(c, op, st, detail)
		},
		Resume: func(c *cli.Context, op cli.Op) (cli.State, string, error) {
			st, detail, err := base.Resume(c, op)
			if err != nil {
				return st, detail, err
			}
			return follow(c, op, st, detail)
		},
	}
}

func standaloneRemoveCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	return &cli.Command{
		Name:  "remove",
		Args:  "NAME",
		Short: "Remove a standalone and its container",
		Flags: func(fs *flag.FlagSet) { fs.Var(&id, "id", "operation `ID` (default: a new one)") },
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			name, err := standaloneName(args, "remove", 0)
			if err != nil {
				return err
			}
			if done, err := g.savedChange(c, s, id.String(), "standalone remove "+name, "standalone-remove"); done {
				return err
			}
			tenant, v, epoch, err := g.standaloneOne(c, s, name)
			if err != nil {
				return err
			}
			op := id.Get()
			target := v.Target
			q := control.StandaloneChange{Tenant: tenant, Name: name, Operation: op, Target: &target}
			impact := fmt.Sprintf("Remove standalone %s; its container and writable layer are lost for good.", name)
			return g.sendAndPrint(c, s, impact, change{ID: op, Summary: "standalone remove " + name, Action: "standalone-remove", Expected: v.Metadata.Revision, Epoch: epoch, Payload: q})
		}),
	}
}

func standaloneKeepCommand(g *globals) *cli.Command {
	var rename, restart string
	var id cli.IDFlag
	return &cli.Command{
		Name:  "keep",
		Args:  "NAME",
		Short: "Make a temporary standalone permanent",
		Long: `Keeps the same container, writable layer and resources; only the time limit
goes. --name renames it and --restart sets what happens when it exits.`,
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&rename, "name", "", "new `NAME`")
			fs.StringVar(&restart, "restart", "", "no, on-failure or always")
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			name, err := standaloneName(args, "keep", 0)
			if err != nil {
				return err
			}
			if rename != "" && !lifecycle.ValidID(rename) {
				return cli.Usagef("--name %q is not a valid name", rename)
			}
			if restart != "" && restart != "no" && restart != "on-failure" && restart != "always" {
				return cli.Usagef("--restart must be no, on-failure or always")
			}
			if done, err := g.savedChange(c, s, id.String(), "standalone keep "+name, "standalone-pin"); done {
				return err
			}
			tenant, v, epoch, err := g.standaloneOne(c, s, name)
			if err != nil {
				return err
			}
			op := id.Get()
			target := v.Target
			q := control.StandaloneChange{Tenant: tenant, Name: name, NewName: rename, Restart: restart, Operation: op, Target: &target}
			impact := fmt.Sprintf("Keep standalone %s with no time limit.", name)
			if rename != "" {
				impact = fmt.Sprintf("Keep standalone %s with no time limit, as %s.", name, rename)
			}
			return g.sendAndPrint(c, s, impact, change{ID: op, Summary: "standalone keep " + name, Action: "standalone-pin", Expected: v.Metadata.Revision, Epoch: epoch, Payload: q})
		}),
	}
}

func standaloneExtendCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	return &cli.Command{
		Name:  "extend",
		Args:  "NAME DURATION",
		Short: "Give a temporary standalone more time",
		Long: `The new expiry is DURATION (such as 2h) from when the server signs the
request, never later than 24h after the standalone was created.`,
		Flags: func(fs *flag.FlagSet) { fs.Var(&id, "id", "operation `ID` (default: a new one)") },
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			name, err := standaloneName(args, "extend", 1)
			if err != nil {
				return err
			}
			d, err := time.ParseDuration(args[1])
			if err != nil || d <= 0 {
				return cli.Usagef("DURATION must be like 30m or 2h")
			}
			ttl, err := wholeSeconds("DURATION", d)
			if err != nil {
				return err
			}
			ch := change{ID: id.Get(), Summary: "standalone extend " + name, Action: "standalone-extend"}
			impact := ""
			saved, err := userauth.LoadOperation(s.Home, s.Client, s.Stored.Session, ch.ID)
			switch {
			case err == nil:
				// The same --id continues the saved extension as it was signed.
				if saved.Operation.Change.Action != ch.Action {
					return fmt.Errorf("--id %s already names a %s change; choose another ID", ch.ID, saved.Operation.Change.Action)
				}
				ch.Expected, ch.Payload = saved.Operation.Change.Expected, saved.Operation.Change.Payload
			case !errors.Is(err, userauth.ErrOperationMissing):
				return err
			default:
				tenant, v, epoch, err := g.standaloneOne(c, s, name)
				if err != nil {
					return err
				}
				m := v.Metadata
				if m.Lifetime != "temp" || m.Cleanup != nil || m.Desired != "running" {
					return cli.ExitError{Code: 3, Err: fmt.Errorf("only a running temporary standalone can be extended (%s is %s, %s)", name, m.Lifetime, standaloneStatus(v))}
				}
				ch.Expected, ch.Epoch = m.Revision, epoch
				ch.Payload = control.StandaloneExtendChange{Tenant: tenant, Name: name, Scope: m.Scope, Operation: ch.ID, CreatedAt: m.CreatedAt, PreviousExpiresAt: m.ExpiresAt, TTLSeconds: ttl, Target: v.Target}
				impact = fmt.Sprintf("Standalone %s expires %s from now (it now has %s left).", name, d, standaloneLeft(v))
			}
			result, sendErr := g.confirmSend(c, s, impact, ch)
			if result == nil {
				return sendErr
			}
			return printExtension(c, g, s, ch.ID, result, sendErr)
		}),
	}
}

// printExtension reports an extension with the expiry arithmetic the
// server signed: the new expiry, the 24h limit and what is left of it. A
// refused extension still says how much time could be asked for.
func printExtension(c *cli.Context, g *globals, s *session, id string, result *state.Result, sendErr error) error {
	st, detail := changeState(*result, false)
	out := map[string]any{"id": id, "state": st, "detail": detail, "result": result, "extension_applied": result.Code == state.Applied}
	var plan control.StandaloneExtensionPlan
	if record, err := userauth.LoadOperation(s.Home, s.Client, s.Stored.Session, id); err == nil {
		if p, err := control.StandaloneExtensionResult(record.Operation); err == nil || result.Code != state.Applied {
			plan = p
			out["extension"] = p
		}
	}
	if err := cli.Print(c.Out, g.output.Format(), out, func() cli.Rows {
		t := cli.Rows{Header: []string{"id", "state", "expires", "latest possible"}}
		expires := "-"
		if result.Code == state.Applied && plan.ProposedExpiresAt != 0 {
			expires = time.Unix(plan.ProposedExpiresAt, 0).UTC().Format(time.RFC3339)
		}
		t.Add(id, st, expires, time.Unix(plan.MaximumExpiresAt, 0).UTC().Format(time.RFC3339))
		return t
	}); err != nil {
		return err
	}
	return sendErr
}

func standaloneLogsCommand(g *globals) *cli.Command {
	var follow bool
	return &cli.Command{
		Name:  "logs",
		Args:  "NAME",
		Short: "Print a standalone's container logs",
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
			fs.String("max-bytes", "", "print at most `N` bytes")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			name, err := standaloneName(args, "logs", 0)
			if err != nil {
				return err
			}
			flow := append([]string{"logs", name}, forward(c, "tail", "since", "until", "cursor", "timestamps", "stdout", "stderr", "max-bytes")...)
			if follow {
				flow = append(flow, "--follow")
			}
			return g.containerReadWith(c, s, follow, g.standaloneFlow, g.standaloneJSON, flow)
		}),
	}
}

func standaloneSampleCommand(g *globals, name, short string) *cli.Command {
	var watch bool
	return &cli.Command{
		Name:  name,
		Args:  "NAME",
		Short: short,
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&watch, "watch", false, "repeat until Ctrl-C")
			fs.String("interval", "", "with --watch, sample every `DURATION` (default 2s)")
			fs.String("max-bytes", "", "print at most `N` bytes")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			standalone, err := standaloneName(args, name, 0)
			if err != nil {
				return err
			}
			flow := append([]string{name, standalone}, forward(c, "interval", "max-bytes")...)
			if watch {
				flow = append(flow, "--watch")
			}
			return g.containerReadWith(c, s, watch, g.standaloneFlow, g.standaloneJSON, flow)
		}),
	}
}

func standaloneInspectCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "inspect",
		Args:  "NAME",
		Short: "Show a standalone's container details and recent lifecycle events",
		Flags: func(fs *flag.FlagSet) {
			fs.String("history", "", "last `N` lifecycle events (default 20, at most 100)")
			fs.String("max-bytes", "", "print at most `N` bytes")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			name, err := standaloneName(args, "inspect", 0)
			if err != nil {
				return err
			}
			ctx, cancel := g.Deadline(c)
			defer cancel()
			var v any
			if err = g.standaloneJSON(ctx, c, s, &v, append([]string{"inspect", name, "--json"}, forward(c, "history", "max-bytes")...)...); err != nil {
				return err
			}
			return cli.Print(c.Out, g.output.Format(), v, nil)
		}),
	}
}

func standaloneExecCommand(g *globals) *cli.Command {
	var interactive, tty bool
	var id cli.IDFlag
	return &cli.Command{
		Name:  "exec",
		Args:  "NAME -- COMMAND [ARG...]",
		Short: "Run a command in a standalone's container",
		Long: `Runs COMMAND once in the running container. -i passes standard input and
-t gives it a terminal. If the connection drops, the command is not started
again; run exec with the same --id to see what became of it.`,
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&interactive, "i", false, "pass standard input")
			fs.BoolVar(&tty, "t", false, "allocate a terminal")
			fs.Var(&id, "id", "exec `ID` (default: a new one)")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			name, err := standaloneName(args, "exec", 0)
			if err != nil {
				return err
			}
			if len(c.Rest) == 0 {
				return cli.Usagef("exec needs a command after --")
			}
			flow := []string{"exec", name, "--operation", id.Get()}
			if interactive {
				flow = append(flow, "-i")
			}
			if tty {
				flow = append(flow, "-t")
			}
			flow = append(append(flow, "--"), c.Rest...)
			ctx, cancel := g.streamContext()
			defer cancel()
			return g.standaloneFlow(ctx, c, s, c.Out, flow...)
		}),
	}
}

func standaloneAttachCommand(g *globals) *cli.Command {
	var interactive, tty bool
	var id cli.IDFlag
	return &cli.Command{
		Name:  "attach",
		Args:  "NAME",
		Short: "Attach to a standalone's main process (a shell with --mode shell)",
		Long: `Connects standard input and output to the container's main process until
Ctrl-C or the process ends. While someone is attached, a temporary
standalone is not removed for being idle.`,
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&interactive, "i", false, "pass standard input")
			fs.BoolVar(&tty, "t", false, "use a terminal")
			fs.Var(&id, "id", "attach `ID` (default: a new one)")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			name, err := standaloneName(args, "attach", 0)
			if err != nil {
				return err
			}
			flow := []string{"attach", name, "--operation", id.Get()}
			if interactive {
				flow = append(flow, "-i")
			}
			if tty {
				flow = append(flow, "-t")
			}
			ctx, cancel := g.streamContext()
			defer cancel()
			return g.standaloneFlow(ctx, c, s, c.Out, flow...)
		}),
	}
}

func init() {
	opKinds["standalone-run"] = standaloneRunHandler
	opKinds["standalone-control"] = standaloneControlHandler
}
