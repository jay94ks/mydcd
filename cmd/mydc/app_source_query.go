// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"strconv"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/userauth"
)

type appSourceOptions struct {
	selection control.AppSourceSelection
	after     string
	raw       bool
}

func parseAppSourceOptions(method string, args []string, diagnostic io.Writer) (appSourceOptions, error) {
	var o appSourceOptions
	if method != "app-source" && method != "app-revisions" {
		return o, errors.New("invalid app source command")
	}
	f := flag.NewFlagSet("manage "+method, flag.ContinueOnError)
	f.SetOutput(diagnostic)
	var app, deployment, revision, section, after onceString
	f.Var(&app, "app", "required app name in the selected tenant")
	f.Var(&deployment, "deployment", "expected app deployment identity")
	if method == "app-source" {
		f.Var(&revision, "revision", "retained source version, default latest")
		f.Var(&section, "section", "source (exact app.yaml), local-services (separate local YAML), overlays (JSON field overrides), or pending-local (local services waiting for the next sync)")
		f.BoolVar(&o.raw, "raw", false, "read every pinned part and write exact document bytes to stdout")
	} else {
		f.Var(&after, "after", "opaque retained-version page cursor")
	}
	if f.Parse(args) != nil || f.NArg() != 0 || len(after.value) > 512 {
		return o, errors.New("invalid app source options")
	}
	o.selection.App, o.selection.Deployment, o.selection.Section, o.after = app.value, deployment.value, section.value, after.value
	if revision.value != "" {
		v, err := strconv.ParseUint(revision.value, 10, 64)
		if err != nil || v == 0 {
			return o, errors.New("revision must be a positive source version")
		}
		o.selection.Revision = v
	}

	// The raw path pins and assembles every part. JSON output is part zero.
	if !o.selection.Valid(method == "app-revisions") {
		return o, errors.New("invalid app source selection; use --raw for all pinned parts")
	}
	return o, nil
}

func runAppSourceQuery(ctx context.Context, method string, args []string, client userauth.Client, peer mydcp.Peer, session access.Session, tenant string, out, diagnostic io.Writer) int {
	o, err := parseAppSourceOptions(method, args, diagnostic)
	if err != nil || tenant == "" {
		if err == nil {
			err = errors.New("app source requires a selected tenant")
		}
		return failure(diagnostic, err, 2)
	}
	if method == "app-revisions" {
		reply, err := client.AppRevisions(ctx, peer, session, tenant, o.selection, o.after)
		if err != nil {
			return userFailure(diagnostic, err)
		}
		return userOutput(out, diagnostic, reply)
	}
	if o.raw {
		raw, _, err := client.ReadAppSource(ctx, peer, session, tenant, o.selection)
		if err != nil {
			return userFailure(diagnostic, err)
		}
		n, err := out.Write(raw)
		if err == nil && n != len(raw) {
			err = io.ErrShortWrite
		}
		if err != nil {
			return failure(diagnostic, err, 1)
		}
		return 0
	}
	reply, err := client.AppSource(ctx, peer, session, tenant, o.selection)
	if err != nil {
		return userFailure(diagnostic, err)
	}
	return userOutput(out, diagnostic, reply)
}
