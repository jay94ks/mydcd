// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"math"

	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/tenancy"
)

// nodeQuotaCommandTree is `sfcli node quota`: the node-wide limit of a
// server. Every tenant limit on the server stays within it.
func nodeQuotaCommandTree(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "quota",
		Short: "Show or set what all tenants together may use on a server (system administrator)",
		Sub:   []*cli.Command{nodeQuotaShowCommand(g), nodeQuotaSetCommand(g)},
	}
}

func nodeLimits(c *cli.Context, g *globals, s *session) (map[string]tenancy.NodeLimit, error) {
	rows, _, err := readResources(c, g, s, "")
	out := map[string]tenancy.NodeLimit{}
	for _, e := range rows {
		if e.Limit != nil && e.Limit.Tenant == "" {
			out[e.Limit.Node] = *e.Limit
		}
	}
	return out, err
}

func nodeQuotaShowCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "show",
		Args:  "NODE",
		Short: "Show a server's node-wide limit",
		Run: func(c *cli.Context, args []string) error {
			node, err := nodeArg(args, "quota show")
			if err != nil {
				return err
			}
			s, err := openSession(g, c)
			if err != nil {
				return err
			}
			defer s.Close()
			limits, err := nodeLimits(c, g, s)
			if err != nil {
				return err
			}
			v, ok := limits[node]
			if !ok {
				return fmt.Errorf("server %s has no node-wide limit; set one with: sfcli node quota set %s --cpu N --memory SIZE", node, node)
			}
			return cli.Print(c.Out, g.output.Format(), v, func() cli.Rows { return nodeLimitRows(v) })
		},
	}
}

func nodeLimitRows(v tenancy.NodeLimit) cli.Rows {
	r := cli.Rows{Header: []string{"limit", "value"}}
	if v.Default {
		// no administrator limit: the server uses everything it has
		r.Add("cpu", "all")
		r.Add("memory", "all (RAM and swap)")
	} else {
		r.Add("cpu", cores(v.Capacity.CPU))
		r.Add("memory", cli.Size(v.Capacity.Memory-v.Swap))
		r.Add("swap", cli.Size(v.Swap))
	}
	r.Add("networks", v.Networks)
	r.Add("consumers", v.MaxConsumers)
	r.Add("packet queue", fmt.Sprintf("%d packets, %s", v.PacketQueuePackets, cli.Size(v.PacketQueueBytes)))
	r.Add("ingress instances", v.MaxIngressInstances)
	r.Add("ingress listeners", v.MaxIngressListeners)
	r.Add("ingress requests", v.MaxIngressRequests)
	r.Add("ingress connections", v.MaxIngressConnections)
	r.Add("ingress buffer", cli.Size(v.IngressBufferBytes))
	r.Add("revision", v.Revision)
	if v.Default {
		r.Add("set by", "server default (no administrator limit)")
	}
	return r
}

func nodeQuotaSetCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var revision cli.RevisionFlag
	var cpu float64
	var memory, swap, packetBytes, ingressBuffer cli.Size
	var networks uint64
	var consumers, packets, instances, listeners, requests, connections int
	return &cli.Command{
		Name:  "set",
		Args:  "NODE --cpu N --memory SIZE [--swap SIZE] [limits]",
		Short: "Set a server's node-wide limit (system administrator)",
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.Var(&revision, "if-revision", "change only if the limit is still at this `revision` (0: new)")
			fs.Float64Var(&cpu, "cpu", 0, "CPU cores (decimals allowed)")
			fs.Var(&memory, "memory", "memory (RAM) `size`, such as 16GiB")
			fs.Var(&swap, "swap", "swap `size` workloads may use on top of --memory (default 0)")
			fs.Uint64Var(&networks, "networks", 0, "managed networks on the server")
			fs.IntVar(&consumers, "consumers", 0, "containers that may join a managed network or DNS")
			fs.IntVar(&packets, "packet-queue", 0, "packets queued per TUN network (0 with --packet-queue-bytes 0: none)")
			fs.Var(&packetBytes, "packet-queue-bytes", "`size` queued per TUN network")
			fs.IntVar(&instances, "ingress-instances", 0, "ingress instances")
			fs.IntVar(&listeners, "ingress-listeners", 0, "ingress listeners")
			fs.IntVar(&requests, "ingress-requests", 0, "ingress requests at a time")
			fs.IntVar(&connections, "ingress-connections", 0, "ingress connections at a time")
			fs.Var(&ingressBuffer, "ingress-buffer", "ingress buffer `size`")
		},
		Run: guard(func(c *cli.Context, args []string) error {
			node, err := nodeArg(args, "quota set")
			if err != nil {
				return err
			}
			if math.IsNaN(cpu) || cpu < 0 || cpu > 1e6 {
				return cli.Usagef("--cpu must be 0 or more cores")
			}
			s, err := openSession(g, c)
			if err != nil {
				return err
			}
			defer s.Close()
			limits, err := nodeLimits(c, g, s)
			if err != nil {
				return err
			}
			old, exists := limits[node]
			// The first administrator limit, also over the server's own
			// default one, starts from NewNodeLimit.
			first := !exists || old.Default
			if first && (!c.Set("cpu") || !c.Set("memory")) {
				return cli.Usagef("a new limit needs --cpu and --memory")
			}
			v := tenancy.NewNodeLimit
			if !first {
				v = old
			}
			v.Tenant, v.Node, v.Owner, v.Revision = "", node, [32]byte{}, 0
			if c.Set("cpu") {
				v.Capacity.CPU = uint64(math.Round(cpu * cpuUnit))
			}
			// Capacity.Memory holds RAM and swap together; Swap is the
			// swap part.
			ram := v.Capacity.Memory - v.Swap
			if c.Set("memory") {
				ram = uint64(memory)
			}
			if c.Set("swap") {
				v.Swap = uint64(swap)
			}
			if ram > ^uint64(0)-v.Swap {
				return cli.Usagef("--memory and --swap are too large")
			}
			v.Capacity.Memory = ram + v.Swap
			setIf := func(name string, dst *int, value int) {
				if c.Set(name) {
					*dst = value
				}
			}
			if c.Set("networks") {
				v.Networks = networks
			}
			setIf("consumers", &v.MaxConsumers, consumers)
			setIf("packet-queue", &v.PacketQueuePackets, packets)
			setIf("packet-queue-bytes", &v.PacketQueueBytes, int(packetBytes))
			setIf("ingress-instances", &v.MaxIngressInstances, instances)
			setIf("ingress-listeners", &v.MaxIngressListeners, listeners)
			setIf("ingress-requests", &v.MaxIngressRequests, requests)
			setIf("ingress-connections", &v.MaxIngressConnections, connections)
			setIf("ingress-buffer", &v.IngressBufferBytes, int(ingressBuffer))
			if (v.PacketQueuePackets == 0) != (v.PacketQueueBytes == 0) {
				return cli.Usagef("--packet-queue and --packet-queue-bytes are both 0 or both set")
			}
			rev, err := revision.Resolve(func() (uint64, error) { return old.Revision, nil })
			if err != nil {
				return err
			}
			if !first {
				fmt.Fprintf(c.Err, "%s: cpu %s -> %s, memory %s -> %s, swap %s -> %s\n", node, cores(old.Capacity.CPU), cores(v.Capacity.CPU), cli.Size(old.Capacity.Memory-old.Swap), cli.Size(v.Capacity.Memory-v.Swap), cli.Size(old.Swap), cli.Size(v.Swap))
			} else {
				fmt.Fprintf(c.Err, "%s: cpu %s, memory %s, swap %s, networks %d, consumers %d (new limit)\n", node, cores(v.Capacity.CPU), cli.Size(v.Capacity.Memory-v.Swap), cli.Size(v.Swap), v.Networks, v.MaxConsumers)
			}
			if err = g.Prompter(c).Confirm("Set the node-wide limit?"); err != nil {
				return err
			}
			summary := fmt.Sprintf("node quota set %s --cpu %s --memory %s", node, cores(v.Capacity.CPU), cli.Size(v.Capacity.Memory))
			if _, err = g.send(c, s, change{Summary: summary, ID: id.Get(), Action: "set-node-quota", Expected: rev, Payload: v}); err != nil {
				return err
			}
			fmt.Fprintf(c.Out, "node-wide limit of %s set\n", node)
			return nil
		}),
	}
}
