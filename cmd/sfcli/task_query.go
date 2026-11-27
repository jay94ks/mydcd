// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"io"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
)

type taskListOptions struct {
	selection control.TaskSelection
	after     string
	all       bool
}

func parseTaskListOptions(args []string, diagnostic io.Writer) (taskListOptions, error) {
	f := flag.NewFlagSet("manage tasks", flag.ContinueOnError)
	f.SetOutput(diagnostic)
	var o taskListOptions
	var node, app, after onceString
	f.Var(&node, "node", "logical node filter")
	f.Var(&app, "app", "named app filter")
	f.Var(&after, "after", "opaque cursor; restart after a revision conflict")
	f.BoolVar(&o.all, "all-tenants", false, "query all currently readable tenants rather than the selected tenant")
	if f.Parse(args) != nil || f.NArg() != 0 || len(after.value) > 512 {
		return o, errors.New("invalid task page options")
	}
	o.selection.Node, o.selection.App, o.after = node.value, app.value, after.value
	if !o.selection.Valid() {
		return o, errors.New("invalid task selector")
	}
	return o, nil
}

func runTaskList(ctx context.Context, args []string, c userauth.Client, peer sfcp.Peer, session access.Session, tenant string, out, diagnostic io.Writer) int {
	o, err := parseTaskListOptions(args, diagnostic)
	if err != nil {
		return failure(diagnostic, err, 2)
	}
	if !o.all {
		o.selection.Tenant = tenant
	}
	reply, err := c.TasksPage(ctx, peer, session, o.selection, o.after)
	if err != nil {
		return userFailure(diagnostic, err)
	}
	return userOutput(out, diagnostic, reply)
}
