// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/userauth"
	"io"
	"strings"
)

func parsePublicRead(args []string, out io.Writer) (control.PublicReadQuery, string, bool, error) {
	if len(args) == 0 || !control.PublicReadMethod(args[0]) {
		return control.PublicReadQuery{}, "", false, errors.New("unknown resource read")
	}
	if strings.HasPrefix(args[0], "vault-") {
		return control.PublicReadQuery{}, "", false, errors.New("Vault reads moved: use mydc secret approvals or secret usages")
	}
	if strings.HasPrefix(args[0], "volume-") {
		return control.PublicReadQuery{}, "", false, errors.New("volume reads moved: use mydc volume users, volume show, volume backup limits or volume files grants")
	}
	flags := flag.NewFlagSet("manage "+args[0], flag.ContinueOnError)
	flags.SetOutput(out)
	var name, app, node, after onceString
	flags.Var(&name, "name", "logical network, Volume, lifecycle script or Vault object name")
	flags.Var(&app, "app", "optional app namespace filter")
	flags.Var(&node, "node", "optional node for backup limits")
	flags.Var(&after, "after", "opaque cursor; restart after source/current-authority changes")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || len(after.value) > 512 {
		return control.PublicReadQuery{}, "", false, errors.New("invalid resource read options")
	}
	query := control.PublicReadQuery{Name: name.value, App: app.value, Node: node.value}
	if !query.Valid(args[0]) {
		return query, "", false, errors.New("selector does not match resource read method")
	}
	return query, after.value, false, nil
}
func runPublicRead(ctx context.Context, args []string, client userauth.Client, peer mydcp.Peer, session access.Session, tenant string, out, diagnostic io.Writer) int {
	query, after, system, err := parsePublicRead(args, diagnostic)
	if err != nil {
		return failure(diagnostic, err, 2)
	}
	if system {
		tenant = ""
	}
	reply, err := client.PublicRead(ctx, peer, session, args[0], tenant, query, after)
	if err != nil {
		return userFailure(diagnostic, err)
	}
	return userOutput(out, diagnostic, reply)
}
