// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/config"
)

// nodeSetEndpointCommand is `sfcli node set-endpoint NODE HOST:PORT`: a
// joined server's address or port changed (a home server's IP often does).
// The cluster records the new endpoint and the leader installs it as the
// server's Raft address; the server itself takes it with `sfcd set-listen`.
func nodeSetEndpointCommand(g *globals) *cli.Command {
	var f changeFlags
	return &cli.Command{
		Name:  "set-endpoint",
		Args:  "NODE HOST:PORT",
		Short: "Change the address of a server that has joined (system administrator)",
		Long: `Records a joined server's new address after its IP or port changed, and
has the leader install it as the server's Raft address. Its vote, key and
containers stay. On the server, set node.yaml 'listen' to the same address
and run 'sfcd set-listen' with sfcd stopped, then start sfcd. For a server
that was added but never joined, use 'sfcli node add NODE --replace'.`,
		Flags: func(fs *flag.FlagSet) { f.register(fs, true, false) },
		Run: func(c *cli.Context, args []string) error {
			if len(args) != 2 {
				return cli.Usagef("set-endpoint needs a node name and HOST:PORT")
			}
			node, err := nodeArg(args[:1], "set-endpoint")
			if err != nil {
				return err
			}
			endpoint := args[1]
			if config.ValidateCanonicalEndpoint(endpoint) != nil {
				return cli.Usagef("%q is not host:port", endpoint)
			}
			s, err := g.open(c)
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			d, err := readNodes(ctx, s)
			cancel()
			if err != nil {
				return err
			}
			e, ok := d.entry(node)
			if !ok {
				return fmt.Errorf("no node %s", node)
			}
			if e.Phase == membership.Invited {
				return cli.ExitError{Code: 3, Err: fmt.Errorf("server %s has not joined yet; register it again with 'sfcli node add %s --replace --endpoint %s ...'", node, node, endpoint)}
			}
			if !membership.FullMember(e) {
				return cli.ExitError{Code: 3, Err: fmt.Errorf("server %s is %s; wait until it has joined", node, e.Phase)}
			}
			if e.Job.Pending != nil {
				return cli.ExitError{Code: 3, Err: fmt.Errorf("server %s has a membership change in progress (%s); try again when it ends", node, e.Phase)}
			}
			if e.Peer.Endpoint == endpoint {
				fmt.Fprintf(c.Err, "%s is already at %s\n", node, endpoint)
				return nil
			}
			fmt.Fprintf(c.Err, "%s: %s -> %s\n", node, e.Peer.Endpoint, endpoint)
			if err := g.apply(c, s, change{Summary: "node set-endpoint " + node + " " + endpoint, ID: f.id.Get(), Action: "set-node-endpoint",
				Expected: f.expect(e.Revision), Payload: control.NodeEndpointChange{ID: node, Endpoint: endpoint}}, false); err != nil {
				return err
			}
			if f.noWait {
				return nil
			}
			return waitEndpoint(c, g, s, node, endpoint)
		},
	}
}

// waitEndpoint waits until the leader has installed the new address.
func waitEndpoint(c *cli.Context, g *globals, s *session, node, endpoint string) error {
	ctx, cancel := g.Deadline(c)
	defer cancel()
	for {
		d, err := readNodes(ctx, s)
		if err == nil {
			if e, ok := d.entry(node); ok && e.Peer.Endpoint == endpoint && e.Job.Pending == nil {
				fmt.Fprintf(c.Err, "%s is now at %s\n", node, endpoint)
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return cli.ExitError{Code: 4, Err: fmt.Errorf("the change was accepted but the new address is not installed yet; check with 'sfcli node show %s' (%w)", node, context.Cause(ctx))}
		case <-time.After(time.Second):
		}
	}
}
