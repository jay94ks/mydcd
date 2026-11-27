// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"io"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
)

type tenantStorageOptions struct{ node, after onceString }

func parseTenantStorageOptions(args []string, out io.Writer) (tenantStorageOptions, error) {
	var o tenantStorageOptions
	f := flag.NewFlagSet("manage tenant-storage", flag.ContinueOnError)
	f.SetOutput(out)
	f.Var(&o.node, "node", "current allowed node filter")
	f.Var(&o.after, "after", "snapshot cursor from the previous tenant root page")
	if err := f.Parse(args); err != nil {
		return o, err
	}
	if f.NArg() != 0 || o.node.set && !lifecycle.ValidID(o.node.value) || len(o.after.value) > 512 {
		return o, errors.New("tenant-storage accepts --node ID and --after CURSOR")
	}
	return o, nil
}
func runTenantStorageQuery(ctx context.Context, args []string, c userauth.Client, peer sfcp.Peer, session access.Session, tenant string, out, diagnostic io.Writer) int {
	o, err := parseTenantStorageOptions(args, diagnostic)
	if err != nil {
		return failure(diagnostic, err, 2)
	}
	if !lifecycle.ValidID(tenant) {
		return failure(diagnostic, errors.New("tenant-storage requires selected --tenant"), 2)
	}
	reply, err := c.TenantStoragePage(ctx, peer, session, tenant, o.node.value, o.after.value)
	if err != nil {
		return userFailure(diagnostic, err)
	}
	return userOutput(out, diagnostic, reply)
}
