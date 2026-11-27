// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/eventlog"
	"github.com/jay94ks/seafield/internal/userauth"
)

// eventsCommand is `sfcli events`: durable diagnostic events.
func eventsCommand(g *globals) *cli.Command {
	var app, node, kind, since string
	var limit int
	var all, follow bool
	return &cli.Command{
		Name:  "events",
		Short: "Show diagnostic events",
		Long: `Shows the diagnostic events of the tenant, oldest first. With --all a
system administrator sees cluster and every tenant's events. -f keeps
reading new events until Ctrl-C.

An empty list does not prove that everything is healthy, and INCOMPLETE
means a gap in collection was seen. Event kinds and retention are in
docs/reference/events.md.`,
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&app, "app", "", "only events of this `app`")
			fs.StringVar(&node, "node", "", "only events of this `node`")
			fs.StringVar(&kind, "kind", "", "only events of this `kind`, such as node-cordoned")
			fs.StringVar(&since, "since", "", "start after this `cursor` (from -o json output)")
			fs.IntVar(&limit, "limit", 100, "show at most this many events (without -f)")
			fs.BoolVar(&all, "all", false, "cluster and all tenants' events (system administrator)")
			fs.BoolVar(&follow, "f", false, "keep reading new events")
		},
		Run: func(c *cli.Context, args []string) error {
			if len(args) != 0 {
				return cli.Usagef("events takes no arguments")
			}
			for _, id := range []string{app, node} {
				if id != "" && !lifecycle.ValidID(id) {
					return cli.Usagef("%q is not a valid name", id)
				}
			}
			if kind != "" && !eventlog.ValidKind(kind) {
				return cli.Usagef("unknown event kind %q", kind)
			}
			if limit < 1 {
				return cli.Usagef("--limit must be at least 1")
			}
			if all && app != "" {
				return cli.Usagef("--app needs a tenant; it cannot be used with --all")
			}
			s, err := g.open(c)
			if err != nil {
				return err
			}
			defer s.Close()
			q := eventlog.Query{App: app, Node: node, Kind: kind, After: since, Limit: 100}
			if !all {
				if q.Tenant, err = g.Tenant(s, true); err != nil {
					return err
				}
			}
			page := eventlog.Page{Schema: 1, Items: []eventlog.Item{}}
			header := true
			for {
				ctx, cancel := g.Deadline(c)
				next, err := s.Client.EventsPage(ctx, s.Target, s.Stored.Session, q)
				cancel()
				if err != nil {
					var remote *userauth.Error
					if errors.As(err, &remote) && remote.Code == "CURSOR_EXPIRED" {
						return errors.New("the cursor is too old; start again without --since")
					}
					if follow && c.Ctx.Err() != nil {
						return nil
					}
					return err
				}
				q.After, page.Cursor, page.Incomplete = next.Cursor, next.Cursor, page.Incomplete || next.Incomplete
				if follow {
					if len(next.Items) > 0 {
						if err := printEvents(c, g, next, header); err != nil {
							return err
						}
						header = false
					}
					if next.More {
						continue
					}
					select {
					case <-c.Ctx.Done():
						return nil
					case <-time.After(2 * time.Second):
					}
					continue
				}
				page.Items = append(page.Items, next.Items...)
				if len(page.Items) >= limit {
					page.Items, page.More = page.Items[:limit], true
					page.Cursor = page.Items[limit-1].Cursor
					break
				}
				if page.More = next.More; !next.More {
					break
				}
			}
			return printEvents(c, g, page, true)
		},
	}
}

func printEvents(c *cli.Context, g *globals, page eventlog.Page, header bool) error {
	if g.output.Format() != cli.Table {
		return cli.Print(c.Out, g.output.Format(), page, nil)
	}
	t := cli.Rows{Header: []string{"time", "kind", "target", "from"}}
	for _, item := range page.Items {
		t.Add(time.UnixMilli(int64(item.At)).Local().Format("2006-01-02 15:04:05"), item.Kind, eventTarget(item.Target), item.SourceNode)
	}
	if page.Incomplete {
		t.Add("INCOMPLETE", "event-source-gap", "some events were not collected", "")
	}
	if !header {
		// Following: later batches continue the same columns without a header.
		for _, row := range t.Rows {
			if _, err := fmt.Fprintln(c.Out, strings.Join(row, "  ")); err != nil {
				return err
			}
		}
		return nil
	}
	return cli.Print(c.Out, cli.Table, page, func() cli.Rows { return t })
}

func eventTarget(t eventlog.Target) string {
	var parts []string
	for _, p := range [][2]string{{"tenant", t.Tenant}, {"app", t.App}, {"service", t.Service}, {"node", t.Node}, {"gateway", t.Gateway}, {"host", t.Host}, {"pair", t.PairID}} {
		if p[1] != "" {
			parts = append(parts, p[0]+"="+p[1])
		}
	}
	return strings.Join(parts, " ")
}
