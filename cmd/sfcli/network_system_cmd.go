// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/network"
)

// networkSystemCommand is sfcli network system: the system network
// sfc-system, which sfcd keeps itself (devel/design/cluster-apps.md 3.1).
func networkSystemCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "system",
		Short: "Show the system network for cluster apps",
		Sub: []*cli.Command{
			networkSystemShowCommand(g),
		},
	}
}

// systemNetworkView is how sfcli network system show prints it.
// Range is fixed; Servers is where each server's own address (its tunnel
// address in every network) comes from.
type systemNetworkView struct {
	Range   string              `json:"range"`
	Servers string              `json:"servers"`
	Users   []string            `json:"users"`
	Members []networkMemberView `json:"members"`
}

func readSystemNetwork(c *cli.Context, g *globals, s *session) (systemNetworkView, error) {
	rows, _, err := readResources(c, g, s, "")
	if err != nil {
		return systemNetworkView{}, err
	}
	v := systemNetworkView{Users: []string{}, Members: []networkMemberView{}}
	found := false
	for _, e := range rows {
		switch {
		case e.System != nil:
			v.Range, v.Servers, found = network.SystemRange.String(), network.ServerBlock.String(), true
			v.Users = append(v.Users, e.System.Users...)
		case e.Network != nil && e.Network.System:
			n := *e.Network
			m := networkMemberView{Node: n.Node, Subnet: poolText(n), Revision: n.Revision}
			if len(n.TunnelAddresses) != 0 {
				m.Tunnel = n.TunnelAddresses[0].String()
			}
			if n.Draining {
				m.Change = "draining"
			}
			v.Members = append(v.Members, m)
		}
	}
	if !found {
		return v, errors.New("the server did not list the system network setting")
	}
	return v, nil
}

func networkSystemShowCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "show",
		Short: "Show the system network: its range, the servers using it and its members",
		Long: `Show the system network sfc-system. sfcd makes it when a server
turns on a cluster app (node.yaml cluster_apps), joins every work server to it, and
removes it once no server uses it. Users are the servers that run cluster apps.
Its range is fixed: each server's own address (its tunnel address in every
network) comes from the server addresses block, and the pools from before it.
Reading it needs the system administrator.`,
		Run: guard(func(c *cli.Context, args []string) error {
			if len(args) != 0 {
				return cli.Usagef("show takes no arguments")
			}
			s, err := openSession(g, c)
			if err != nil {
				return err
			}
			defer s.Close()
			v, err := readSystemNetwork(c, g, s)
			if err != nil {
				return err
			}
			return cli.Print(c.Out, g.output.Format(), v, func() cli.Rows {
				users := "(none)"
				if len(v.Users) != 0 {
					users = strings.Join(v.Users, ",")
				}
				fmt.Fprintf(c.Out, "Range: %s\nServer addresses: %s\nUsed by: %s\n\n", v.Range, v.Servers, users)
				r := cli.Rows{Header: []string{"node", "subnet", "tunnel", "state"}}
				for _, m := range v.Members {
					state := "configured"
					if m.Change != "" {
						state = m.Change
					}
					r.Add(m.Node, m.Subnet, m.Tunnel, state)
				}
				return r
			})
		}),
	}
}
