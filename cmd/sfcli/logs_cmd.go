// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strconv"

	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
)

// logsTarget is what one `sfcli logs` reads. The aliases (app logs,
// standalone logs, node logs) fill it from their arguments and call the
// same runLogs.
type logsTarget struct {
	App        string
	Container  string
	Instance   string
	Standalone string
	Node       string
	Name       string // cluster app on Node
}

const logsLong = `Prints the last 200 lines. -f keeps printing new lines until Ctrl-C.

Pick the target with options:
  --app APP --container CONTAINER [--instance TASK]   a container of an app
  --standalone NAME                                   a standalone
  --node NODE NAME                                    a cluster app (such as web) on a server
  --node NODE --container CONTAINER                   any stored container log on a server

--container alone never picks a container of an app. --node needs a
system administrator and reads what that server keeps, so a container that
is already gone can still be read.`

// logsFlags registers the options every logs command shares.
func logsFlags(fs *flag.FlagSet, follow *bool) {
	fs.BoolVar(follow, "f", false, "follow new lines")
	fs.String("tail", "", "last `N` lines (at most 10000)")
	fs.String("since", "", "from this RFC3339 `time`")
	fs.String("until", "", "up to this RFC3339 `time`")
	fs.String("cursor", "", "continue from this `CURSOR`")
	fs.Bool("timestamps", false, "show timestamps")
	fs.Bool("stdout", false, "only standard output")
	fs.Bool("stderr", false, "only standard error")
	fs.String("max-bytes", "", "print at most `N` bytes")
}

func logsCommand(g *globals) *cli.Command {
	var follow bool
	var t logsTarget
	return &cli.Command{
		Name:  "logs",
		Args:  "[NAME]",
		Short: "Print a container's logs (app, standalone or server)",
		Long:  logsLong,
		Flags: func(fs *flag.FlagSet) {
			logsFlags(fs, &follow)
			fs.StringVar(&t.App, "app", "", "the `APP` (with --container)")
			fs.StringVar(&t.Container, "container", "", "the `CONTAINER` (with --app or --node)")
			fs.StringVar(&t.Instance, "instance", "", "one `TASK` of a container with several (with --app)")
			fs.StringVar(&t.Standalone, "standalone", "", "the standalone `NAME`")
			fs.StringVar(&t.Node, "node", "", "the server `NODE` that keeps the log")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			switch {
			case len(args) > 1:
				return cli.Usagef("logs takes at most one NAME")
			case len(args) == 1:
				t.Name = args[0]
			}
			return g.runLogs(c, s, t, follow)
		}),
	}
}

// runLogs is the one implementation behind sfcli logs and its aliases.
func (g *globals) runLogs(c *cli.Context, s *session, t logsTarget, follow bool) error {
	common := forward(c, "tail", "since", "until", "cursor", "timestamps", "stdout", "stderr", "max-bytes")
	switch {
	case t.Node != "":
		if t.App != "" || t.Standalone != "" || t.Instance != "" {
			return cli.Usagef("--node takes NAME or --container, not --app, --standalone or --instance")
		}
		if (t.Name == "") == (t.Container == "") {
			return cli.Usagef("--node needs a cluster app NAME or --container CONTAINER")
		}
		return g.nodeLogs(c, s, t, follow)
	case t.App != "":
		if t.Standalone != "" || t.Name != "" {
			return cli.Usagef("--app takes --container, not --standalone or NAME")
		}
		if t.Container == "" {
			return cli.Usagef("--app needs --container CONTAINER")
		}
		flow := append([]string{"logs", "-p", t.App, t.Container}, common...)
		if t.Instance != "" {
			flow = append(flow, "--instance="+t.Instance)
		}
		if follow {
			flow = append(flow, "--follow")
		}
		return g.containerRead(c, s, follow, flow)
	case t.Standalone != "":
		if t.Container != "" || t.Instance != "" || t.Name != "" {
			return cli.Usagef("--standalone takes no --container, --instance or NAME")
		}
		flow := append([]string{"logs", t.Standalone}, common...)
		if follow {
			flow = append(flow, "--follow")
		}
		return g.containerReadWith(c, s, follow, g.standaloneFlow, g.standaloneJSON, flow)
	case t.Container != "":
		return cli.Usagef("--container needs --app APP or --node NODE")
	}
	return cli.Usagef("logs needs --app, --standalone or --node")
}

// nodeLogsQuery turns the shared options into a node-logs query.
func nodeLogsQuery(c *cli.Context, t logsTarget, follow bool) (control.NodeLogsQuery, int, error) {
	q := control.NodeLogsQuery{Node: t.Node, App: t.Name, Container: t.Container, Tail: 200, Wait: follow}
	if !lifecycle.ValidID(t.Node) {
		return q, 0, cli.Usagef("%q is not a valid node name", t.Node)
	}
	str := func(name string) string { return c.Flags.Lookup(name).Value.String() }
	if c.Set("tail") {
		n, err := strconv.Atoi(str("tail"))
		if err != nil || n < 1 || n > 10000 {
			return q, 0, cli.Usagef("--tail needs a number from 1 to 10000")
		}
		q.Tail = n
	}
	if c.Set("cursor") {
		n, err := strconv.ParseUint(str("cursor"), 10, 64)
		if err != nil {
			return q, 0, cli.Usagef("--cursor needs a cursor printed by an earlier read")
		}
		q.After, q.Tail = n, 0
	}
	q.Since, q.Until = str("since"), str("until")
	q.Timestamps = c.Set("timestamps")
	q.Stdout, q.Stderr = c.Set("stdout"), c.Set("stderr")
	if !q.Stdout && !q.Stderr {
		q.Stdout, q.Stderr = true, true
	}
	limit := 0
	if c.Set("max-bytes") {
		n, err := strconv.Atoi(str("max-bytes"))
		if err != nil || n <= 0 {
			return q, 0, cli.Usagef("--max-bytes needs a positive number")
		}
		limit = n
	}
	if follow && q.Until != "" {
		return q, 0, cli.Usagef("-f cannot be used with --until")
	}
	if !q.Valid() {
		return q, 0, cli.Usagef("invalid logs options (check the times, container name and app name)")
	}
	return q, limit, nil
}

// nodeLogs reads pages of a stored log on one server until the end (or,
// with -f, until Ctrl-C). Standard error lines go to the error stream.
func (g *globals) nodeLogs(c *cli.Context, s *session, t logsTarget, follow bool) error {
	q, limit, err := nodeLogsQuery(c, t, follow)
	if err != nil {
		return err
	}
	format := g.output.Format()
	if follow && format == cli.YAML {
		return cli.Usagef("-o yaml cannot follow; use -o json")
	}
	var ctx context.Context
	var cancel context.CancelFunc
	if follow {
		ctx, cancel = g.streamContext()
	} else {
		ctx, cancel = g.Deadline(c)
	}
	defer cancel()
	var all []control.NodeLogLine
	var last control.NodeLogsPage
	printed := 0
	enc := json.NewEncoder(c.Out)
	for {
		page, err := s.Client.NodeLogs(ctx, s.Target, s.Stored.Session, q)
		if err != nil {
			if follow && ctx.Err() != nil {
				return nil
			}
			return err
		}
		switch page.Code {
		case "not-found":
			return cli.ExitError{Code: 1, Err: fmt.Errorf("no stored log matches on %s", q.Node)}
		case "ambiguous":
			return cli.ExitError{Code: 1, Err: fmt.Errorf("container %q names several logs on %s; give more of the ID", q.Container, q.Node)}
		}
		if limit > 0 {
			all := page.Lines
			page.Lines, printed = limitLines(page.Lines, limit, printed)
			if len(page.Lines) < len(all) {
				// Continue right after the last printed line, not after
				// the lines left out.
				page.Next, page.More = all[len(page.Lines)].Seq-1, true
			}
		}
		switch format {
		case cli.JSON:
			if err := enc.Encode(page); err != nil {
				return err
			}
		case cli.YAML:
			all = append(all, page.Lines...)
		default:
			writeNodeLogLines(c.Out, c.Err, page.Lines, q.Timestamps)
		}
		last = page
		if limit > 0 && printed >= limit {
			fmt.Fprintf(c.Err, "more lines; continue with --cursor %d\n", page.Next)
			break
		}
		if !page.More && !follow {
			break
		}
		q.After, q.Tail = page.Next, 0
		if ctx.Err() != nil {
			return nil
		}
	}
	if format == cli.YAML {
		last.Lines = all
		return cli.Print(c.Out, cli.YAML, last, nil)
	}
	return nil
}

// limitLines keeps the lines that fit in limit bytes after printed.
func limitLines(lines []control.NodeLogLine, limit, printed int) ([]control.NodeLogLine, int) {
	for i, line := range lines {
		if printed+len(line.Data) > limit {
			return lines[:i], limit
		}
		printed += len(line.Data)
	}
	return lines, printed
}

func writeNodeLogLines(out, errOut io.Writer, lines []control.NodeLogLine, timestamps bool) {
	for _, line := range lines {
		w := out
		if line.Stderr {
			w = errOut
		}
		if timestamps {
			fmt.Fprintf(w, "%s ", line.Time)
		}
		_, _ = w.Write(line.Data)
		if !line.Partial {
			_, _ = io.WriteString(w, "\n")
		}
	}
}

// nodeLogsCommand is `sfcli node logs NODE NAME`, an alias of
// `sfcli logs --node NODE NAME`.
func nodeLogsCommand(g *globals) *cli.Command {
	var follow bool
	var container string
	return &cli.Command{
		Name:  "logs",
		Args:  "NODE [NAME]",
		Short: "Print a cluster app's (or --container's) logs on a server (same as sfcli logs --node)",
		Long:  `Same as sfcli logs --node NODE NAME. --container reads any stored container log on that server instead.`,
		Flags: func(fs *flag.FlagSet) {
			logsFlags(fs, &follow)
			fs.StringVar(&container, "container", "", "any stored `CONTAINER` (name or ID) instead of NAME")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) < 1 || len(args) > 2 {
				return cli.Usagef("node logs needs NODE and NAME (or --container)")
			}
			t := logsTarget{Node: args[0], Container: container}
			if len(args) == 2 {
				t.Name = args[1]
			}
			return g.runLogs(c, s, t, follow)
		}),
	}
}
