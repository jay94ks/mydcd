// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"slices"
	"strings"

	"github.com/jay94ks/mydcd/internal/cli"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/nodestorage"
)

// nodeStorageCommandTree is `mydc node storage`: directories on servers
// that volumes and registries may use.
func nodeStorageCommandTree(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "storage",
		Short: "Manage the storage directories of servers",
		Long: `A storage directory is an existing directory on a server that volumes
and registries may be placed in. mydc never formats, mounts, creates or
deletes the directory itself.`,
		Sub: []*cli.Command{
			nodeStorageListCommand(g),
			nodeStorageShowCommand(g),
			nodeStorageSpaceCommand(g),
			nodeStorageAddCommand(g),
			nodeStorageSetCommand(g),
			nodeStorageSelectCommand(g, "drain", "Stop placing new volumes in a storage directory", "drain-node-storage"),
			nodeStorageSelectCommand(g, "remove", "Forget a drained, empty storage directory", "remove-node-storage"),
		},
	}
}

type storageList struct {
	Revision     uint64             `json:"revision"`
	RootRevision uint64             `json:"root_revision"`
	Roots        []nodestorage.Root `json:"roots"`
}

// readStorage reads every system storage page, optionally for one node.
func readStorage(ctx context.Context, s *session, node string) (storageList, error) {
	var l storageList
	l.Roots = []nodestorage.Root{}
	after := ""
	for first := true; ; first = false {
		reply, err := s.Client.NodeStoragePage(ctx, s.Target, s.Stored.Session, node, after)
		if err != nil {
			return l, err
		}
		if !first && (l.Revision != reply.NodeStorageRevision || l.RootRevision != reply.NodeStorageRootRevision) {
			return l, errors.New("storage changed while it was read; try again")
		}
		l.Revision, l.RootRevision = reply.NodeStorageRevision, reply.NodeStorageRootRevision
		if len(reply.NodeStorage) > 8 || len(l.Roots)+len(reply.NodeStorage) > 1024 {
			return l, errors.New("server sent an invalid storage page")
		}
		for _, root := range reply.NodeStorage {
			key := root.Definition.Node + "/" + root.Definition.ID
			if key <= after || node != "" && root.Definition.Node != node || root.Reference(s.Client.Cluster).Validate() != nil {
				return l, errors.New("server sent an invalid storage page")
			}
			l.Roots = append(l.Roots, root)
			after = key
		}
		if reply.NodeStorageNext == "" {
			return l, nil
		}
		if len(reply.NodeStorage) == 0 || reply.NodeStorageNext != after {
			return l, errors.New("server sent an invalid storage cursor")
		}
	}
}

func (l storageList) find(node, name string) (nodestorage.Root, bool) {
	for _, r := range l.Roots {
		if r.Definition.Node == node && r.Definition.ID == name {
			return r, true
		}
	}
	return nodestorage.Root{}, false
}

func storageState(r nodestorage.Root) string {
	switch {
	case r.Closed != nil:
		return "removed"
	case r.Draining:
		return "draining"
	case r.Attestation == nil:
		return "pending"
	}
	return "ready"
}

func nodeAndName(args []string, what string) (string, string, error) {
	if len(args) != 2 || !lifecycle.ValidID(args[0]) || !lifecycle.ValidID(args[1]) {
		return "", "", cli.Usagef("%s needs NODE NAME", what)
	}
	return args[0], args[1], nil
}

func nodeStorageListCommand(g *globals) *cli.Command {
	var all bool
	return &cli.Command{
		Name:  "list",
		Args:  "[NODE]",
		Short: "List storage directories",
		Long:  "Lists the directories the tenant may use, with --all every directory (system administrator).",
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&all, "all", false, "every directory with its settings (system administrator)")
		},
		Run: func(c *cli.Context, args []string) error {
			node := ""
			if len(args) > 0 {
				var err error
				if node, err = nodeArg(args, "list"); err != nil {
					return err
				}
			}
			s, err := g.open(c)
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			defer cancel()
			if all {
				l, err := readStorage(ctx, s, node)
				if err != nil {
					return err
				}
				return cli.Print(c.Out, g.output.Format(), l, func() cli.Rows {
					t := cli.Rows{Header: []string{"node", "name", "path", "state", "tenants", "max volumes"}}
					for _, r := range l.Roots {
						t.Add(r.Definition.Node, r.Definition.ID, r.Definition.Path, storageState(r), strings.Join(r.Definition.Tenants, ","), r.Definition.MaxVolumes)
					}
					return t
				})
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			items := []control.TenantStorageRoot{}
			after := ""
			for pages := 0; ; pages++ {
				if pages == 256 {
					return errors.New("too many storage pages")
				}
				reply, err := s.Client.TenantStoragePage(ctx, s.Target, s.Stored.Session, tenant, node, after)
				if err != nil {
					return err
				}
				items = append(items, reply.TenantStorage...)
				if after = reply.TenantStorageNext; after == "" {
					break
				}
			}
			return cli.Print(c.Out, g.output.Format(), items, func() cli.Rows {
				t := cli.Rows{Header: []string{"node", "name", "allowed", "draining"}}
				for _, r := range items {
					t.Add(r.Node, r.ID, r.Allowed, r.Draining)
				}
				return t
			})
		},
	}
}

func nodeStorageShowCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "show",
		Args:  "NODE NAME",
		Short: "Show one storage directory (system administrator)",
		Run: func(c *cli.Context, args []string) error {
			node, name, err := nodeAndName(args, "show")
			if err != nil {
				return err
			}
			s, err := g.open(c)
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			defer cancel()
			l, err := readStorage(ctx, s, node)
			if err != nil {
				return err
			}
			r, ok := l.find(node, name)
			if !ok {
				return fmt.Errorf("no storage %s on %s", name, node)
			}
			return cli.Print(c.Out, g.output.Format(), r, nil)
		},
	}
}

func nodeStorageSpaceCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "space",
		Args:  "[NODE]",
		Short: "Show free space per filesystem (system administrator)",
		Long:  "Asks each server for the space of its storage directories now and adds them up per filesystem. It is an observation, not a reservation.",
		Run: func(c *cli.Context, args []string) error {
			node := ""
			if len(args) > 0 {
				var err error
				if node, err = nodeArg(args, "space"); err != nil {
					return err
				}
			}
			s, err := g.open(c)
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			defer cancel()
			l, err := readStorage(ctx, s, node)
			if err != nil {
				return err
			}
			var samples []nodestorage.Space
			for _, root := range l.Roots {
				if root.Closed != nil {
					continue
				}
				if root.Attestation == nil || root.Draining {
					return fmt.Errorf("storage %s/%s is %s; space needs every directory ready", root.Definition.Node, root.Definition.ID, storageState(root))
				}
				reply, err := s.Client.NodeStorageSpace(ctx, s.Target, s.Stored.Session, control.NodeStorageSelection{Node: root.Definition.Node, ID: root.Definition.ID})
				if err != nil {
					return err
				}
				if reply.NodeStorageRevision != l.Revision || reply.NodeStorageRootRevision != l.RootRevision || reply.NodeStorageSpace == nil || reply.NodeStorageSpace.Root != root.Reference(s.Client.Cluster) || !reply.NodeStorageSpace.Directory.MatchesOriginal(root.Attestation.Directory) {
					return errors.New("storage changed while space was read; try again")
				}
				samples = append(samples, *reply.NodeStorageSpace)
			}
			pools, err := nodestorage.AggregateSpaces(samples)
			if err != nil {
				return err
			}
			return cli.Print(c.Out, g.output.Format(), pools, nil)
		},
	}
}

// storageTenants parses --tenants a,b into a sorted unique list.
func storageTenants(list string) ([]string, error) {
	if list == "" {
		return nil, nil
	}
	out := strings.Split(list, ",")
	slices.Sort(out)
	for i, id := range out {
		if !lifecycle.ValidID(id) || i > 0 && out[i-1] == id {
			return nil, cli.Usagef("--tenants needs unique tenant names")
		}
	}
	return out, nil
}

func nodeStorageAddCommand(g *globals) *cli.Command {
	var f changeFlags
	var path, tenants string
	var maxVolumes int
	return &cli.Command{
		Name:  "add",
		Args:  "NODE NAME",
		Short: "Register an existing directory as storage (system administrator)",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&path, "path", "", "existing absolute `directory` on the server")
			fs.StringVar(&tenants, "tenants", "", "tenants that may use it, comma separated (default none)")
			fs.IntVar(&maxVolumes, "max-volumes", 256, "most volumes it may hold (1..256)")
			f.register(fs, false, false)
		},
		Run: func(c *cli.Context, args []string) error {
			node, name, err := nodeAndName(args, "add")
			if err != nil {
				return err
			}
			if nodestorage.ValidateRootPath(path) != nil {
				return cli.Usagef("--path must be an absolute directory other than /")
			}
			if maxVolumes < 1 || maxVolumes > 256 {
				return cli.Usagef("--max-volumes must be 1..256")
			}
			list, err := storageTenants(tenants)
			if err != nil {
				return err
			}
			s, err := g.open(c)
			if err != nil {
				return err
			}
			defer s.Close()
			return g.apply(c, s, change{Summary: "node storage add " + node + " " + name, ID: f.id.Get(), Action: "add-node-storage",
				Payload: nodestorage.Definition{Node: node, ID: name, Path: path, Tenants: list, MaxVolumes: maxVolumes}}, false)
		},
	}
}

func nodeStorageSetCommand(g *globals) *cli.Command {
	var f changeFlags
	var tenants string
	var noTenants bool
	var maxVolumes int
	return &cli.Command{
		Name:  "set",
		Args:  "NODE NAME",
		Short: "Change who may use a storage directory and how much (system administrator)",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&tenants, "tenants", "", "tenants that may use it, comma separated")
			fs.BoolVar(&noTenants, "no-tenants", false, "no tenant may place new volumes")
			fs.IntVar(&maxVolumes, "max-volumes", 0, "most volumes it may hold (1..256; default unchanged)")
			f.register(fs, false, false)
		},
		Run: func(c *cli.Context, args []string) error {
			node, name, err := nodeAndName(args, "set")
			if err != nil {
				return err
			}
			if noTenants && tenants != "" {
				return cli.Usagef("--tenants and --no-tenants cannot be used together")
			}
			list, err := storageTenants(tenants)
			if err != nil {
				return err
			}
			s, err := g.open(c)
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			defer cancel()
			l, err := readStorage(ctx, s, node)
			if err != nil {
				return err
			}
			r, ok := l.find(node, name)
			if !ok {
				return fmt.Errorf("no storage %s on %s", name, node)
			}
			q := control.NodeStoragePolicy{Node: node, ID: name, Tenants: r.Definition.Tenants, MaxVolumes: r.Definition.MaxVolumes}
			if tenants != "" || noTenants {
				q.Tenants = list
			}
			if c.Set("max-volumes") {
				if maxVolumes < 1 || maxVolumes > 256 {
					return cli.Usagef("--max-volumes must be 1..256")
				}
				q.MaxVolumes = maxVolumes
			}
			return g.apply(c, s, change{Summary: "node storage set " + node + " " + name, ID: f.id.Get(), Action: "set-node-storage-policy",
				Expected: f.expect(r.Revision), Payload: q}, false)
		},
	}
}

func nodeStorageSelectCommand(g *globals, verb, short, action string) *cli.Command {
	var f changeFlags
	return &cli.Command{
		Name:  verb,
		Args:  "NODE NAME",
		Short: short + " (system administrator)",
		Flags: func(fs *flag.FlagSet) { f.register(fs, false, false) },
		Run: func(c *cli.Context, args []string) error {
			node, name, err := nodeAndName(args, verb)
			if err != nil {
				return err
			}
			s, err := g.open(c)
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			defer cancel()
			l, err := readStorage(ctx, s, node)
			if err != nil {
				return err
			}
			r, ok := l.find(node, name)
			if !ok {
				return fmt.Errorf("no storage %s on %s", name, node)
			}
			if verb == "remove" {
				if err := g.Prompter(c).Confirm("Remove storage " + name + " from " + node + "?"); err != nil {
					return err
				}
			}
			return g.apply(c, s, change{Summary: "node storage " + verb + " " + node + " " + name, ID: f.id.Get(), Action: action,
				Expected: f.expect(r.Revision), Payload: control.NodeStorageSelection{Node: node, ID: name}}, false)
		},
	}
}
