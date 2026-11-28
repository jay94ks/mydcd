// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"flag"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/cliprofile"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/internal/workload"
)

// tenant: 작업 공간 (devel/design/cli-and-formats.md, 작업 공간·사용자·망).

const cpuUnit = 1e9 // NodeLimit CPU is in billionths of a core

func tenantCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "tenant",
		Short: "Manage tenants (작업 공간), their members, servers and limits",
		Sub: []*cli.Command{
			tenantListCommand(g),
			tenantShowCommand(g),
			tenantStatusCommand(g),
			tenantCreateCommand(g),
			tenantSetCommand(g),
			tenantDeleteCommand(g),
			tenantMembersCommand(g),
			tenantMemberCommand(g),
			tenantResourcesCommand(g),
			tenantQuotaCommand(g),
			tenantTrustCommand(g),
		},
	}
}

func tenantArg(args []string, usage string) (string, error) {
	if len(args) != 1 {
		return "", cli.Usagef("expected %s", usage)
	}
	if !cli.ValidID(args[0]) {
		return "", cli.Usagef("%q is not a valid tenant name", args[0])
	}
	return args[0], nil
}

func tenantListCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "list",
		Short: "List the tenants you belong to",
		Run: guard(func(c *cli.Context, args []string) error {
			if len(args) != 0 {
				return cli.Usagef("list takes no arguments")
			}
			s, err := openSession(g, c)
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			defer cancel()
			reply, err := s.Client.Tenants(ctx, s.Target, s.Stored.Session)
			if err != nil {
				return err
			}
			tenants := reply.Tenants
			if tenants == nil {
				tenants = []userauth.TenantView{}
			}
			return cli.Print(c.Out, g.output.Format(), tenants, func() cli.Rows {
				r := cli.Rows{Header: []string{"name", "role", "servers"}}
				for _, t := range tenants {
					r.Add(t.ID, t.Role, strings.Join(t.AllowedNodes, ","))
				}
				return r
			})
		}),
	}
}

// tenantView is one tenant: its record revision, servers and members.
type tenantView struct {
	Name     string                `json:"name"`
	Revision uint64                `json:"revision"`
	Servers  []string              `json:"servers"`
	Members  []access.TenantMember `json:"members"`
}

func readTenant(c *cli.Context, g *globals, s *session, tenant string) (tenantView, error) {
	v := tenantView{Name: tenant, Servers: []string{}, Members: []access.TenantMember{}}
	after := ""
	for {
		ctx, cancel := g.Deadline(c)
		reply, err := s.Client.TenantMembers(ctx, s.Target, s.Stored.Session, tenant, after)
		cancel()
		if err != nil {
			return v, err
		}
		if after == "" {
			v.Revision = reply.TenantRevision
			if reply.AllowedNodes != nil {
				v.Servers = reply.AllowedNodes
			}
		} else if reply.TenantRevision != v.Revision {
			return v, errors.New("the tenant changed while reading it; try again")
		}
		v.Members = append(v.Members, reply.Members...)
		if reply.Next == "" {
			return v, nil
		}
		after = reply.Next
	}
}

func tenantShowCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "show",
		Args:  "TENANT",
		Short: "Show a tenant's servers and members",
		Run: guard(func(c *cli.Context, args []string) error {
			tenant, err := tenantArg(args, "TENANT")
			if err != nil {
				return err
			}
			s, err := openSession(g, c)
			if err != nil {
				return err
			}
			defer s.Close()
			v, err := readTenant(c, g, s, tenant)
			if err != nil {
				return err
			}
			return cli.Print(c.Out, g.output.Format(), v, nil)
		}),
	}
}

func tenantStatusCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "status",
		Args:  "TENANT",
		Short: "Show a tenant's record and, while it is being deleted, what remains (system administrator)",
		Run: guard(func(c *cli.Context, args []string) error {
			tenant, err := tenantArg(args, "TENANT")
			if err != nil {
				return err
			}
			s, err := openSession(g, c)
			if err != nil {
				return err
			}
			defer s.Close()
			var v control.TenantRetirementStatus
			after := ""
			for {
				ctx, cancel := g.Deadline(c)
				page, err := s.Client.TenantRetirement(ctx, s.Target, s.Stored.Session, tenant, after)
				cancel()
				if err != nil {
					return err
				}
				if after == "" {
					v = page
				} else if page.Tenant.Revision != v.Tenant.Revision || page.Index != v.Index {
					return errors.New("the tenant changed while reading it; try again")
				} else {
					v.Remaining = append(v.Remaining, page.Remaining...)
				}
				if page.Next == "" {
					v.Next = ""
					break
				}
				after = page.Next
			}
			return cli.Print(c.Out, g.output.Format(), v, func() cli.Rows {
				r := cli.Rows{Header: []string{"tenant", "phase", "revision", "remaining", "closed servers"}}
				r.Add(v.Tenant.ID, string(v.Tenant.Phase), fmt.Sprint(v.Tenant.Revision), fmt.Sprint(v.RemainingCount), fmt.Sprintf("%d/%d", v.ClosedOwners, v.OwnerCount))
				return r
			})
		}),
	}
}

func tenantMembersCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "members",
		Args:  "TENANT",
		Short: "List a tenant's members and their roles",
		Run: guard(func(c *cli.Context, args []string) error {
			tenant, err := tenantArg(args, "TENANT")
			if err != nil {
				return err
			}
			s, err := openSession(g, c)
			if err != nil {
				return err
			}
			defer s.Close()
			v, err := readTenant(c, g, s, tenant)
			if err != nil {
				return err
			}
			return cli.Print(c.Out, g.output.Format(), v.Members, func() cli.Rows {
				r := cli.Rows{Header: []string{"user", "role", "enabled", "revision"}}
				for _, m := range v.Members {
					role := string(m.Role)
					if m.Implicit {
						role += " (system admin)"
					}
					r.Add(m.Username, role, m.Enabled && m.AccountEnabled, m.Revision)
				}
				return r
			})
		}),
	}
}

func parseNodes(text string) ([]string, error) {
	nodes := []string{}
	if text == "" {
		return nodes, nil
	}
	seen := map[string]bool{}
	for _, n := range strings.Split(text, ",") {
		if !cliprofile.ValidKeyName(n) || seen[n] {
			return nil, cli.Usagef("--nodes must be distinct server names separated by commas")
		}
		seen[n] = true
		nodes = append(nodes, n)
	}
	return nodes, nil
}

func tenantCreateCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var nodes string
	return &cli.Command{
		Name:  "create",
		Args:  "TENANT",
		Short: "Create a tenant (system administrator)",
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.StringVar(&nodes, "nodes", "", "servers the tenant may use, separated by commas")
		},
		Run: guard(func(c *cli.Context, args []string) error {
			tenant, err := tenantArg(args, "TENANT")
			if err != nil {
				return err
			}
			servers, err := parseNodes(nodes)
			if err != nil {
				return err
			}
			s, err := openSession(g, c)
			if err != nil {
				return err
			}
			defer s.Close()
			opID := id.Get()
			fmt.Fprintf(c.Err, "Creating tenant %s (operation %s)\n", tenant, opID)
			if _, err = g.send(c, s, change{Summary: "tenant create " + tenant, ID: opID, Action: "create-tenant", Expected: 0, Payload: control.TenantID{ID: tenant}}); err != nil {
				return err
			}
			if len(servers) > 0 {
				v, err := readTenant(c, g, s, tenant)
				if err != nil {
					return err
				}
				if _, err = g.send(c, s, change{Summary: "tenant set " + tenant + " --nodes " + nodes, ID: opID + "-nodes", Action: "set-nodes", Expected: v.Revision, Payload: control.NodeChange{Tenant: tenant, Add: servers}}); err != nil {
					return err
				}
			}
			fmt.Fprintf(c.Out, "tenant %s created\n", tenant)
			return nil
		}),
	}
}

func tenantSetCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var revision cli.RevisionFlag
	var nodes string
	return &cli.Command{
		Name:  "set",
		Args:  "TENANT --nodes NODE,...",
		Short: "Set the servers a tenant may use (system administrator)",
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.Var(&revision, "if-revision", "change only if the tenant is still at this `revision`")
			fs.StringVar(&nodes, "nodes", "", "servers the tenant may use, separated by commas; empty for none")
		},
		Run: guard(func(c *cli.Context, args []string) error {
			tenant, err := tenantArg(args, "TENANT --nodes NODE,...")
			if err != nil {
				return err
			}
			if !c.Set("nodes") {
				return cli.Usagef("give --nodes")
			}
			servers, err := parseNodes(nodes)
			if err != nil {
				return err
			}
			s, err := openSession(g, c)
			if err != nil {
				return err
			}
			defer s.Close()
			// The change carries only the servers added and removed, made
			// from the list read now; --if-revision must still match it.
			current, err := readTenant(c, g, s, tenant)
			if err != nil {
				return err
			}
			rev, err := revision.Resolve(func() (uint64, error) { return current.Revision, nil })
			if err != nil {
				return err
			}
			if rev != current.Revision {
				return fmt.Errorf("tenant %s changed: it is at revision %d, not %d", tenant, current.Revision, rev)
			}
			delta := control.NodeChangeTo(tenant, current.Servers, servers)
			if len(delta.Add)+len(delta.Remove) == 0 {
				fmt.Fprintf(c.Out, "tenant %s already uses %s\n", tenant, listOrNone(servers))
				return nil
			}
			fmt.Fprintf(c.Err, "Servers of %s: %s -> %s\n", tenant, listOrNone(current.Servers), listOrNone(servers))
			if err = g.Prompter(c).Confirm("Change the servers?"); err != nil {
				return err
			}
			opID := id.Get()
			if _, err = g.send(c, s, change{Summary: "tenant set " + tenant + " --nodes " + nodes, ID: opID, Action: "set-nodes", Expected: rev, Payload: delta}); err != nil {
				return err
			}
			fmt.Fprintf(c.Out, "tenant %s servers set\n", tenant)
			return nil
		}),
	}
}

func listOrNone(v []string) string {
	if len(v) == 0 {
		return "(none)"
	}
	return strings.Join(v, ",")
}

// tenant delete is the whole retirement: begin blocks new work, then once
// every app, network, registry and data the tenant owns is gone and every
// server has reported its part closed, finish removes it. Remaining
// resources are listed and the command waits for them; Ctrl-C or --no-wait
// leaves the operation for 'sfcli op resume'.
func tenantDeleteCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var revision cli.RevisionFlag
	var noWait bool
	return &cli.Command{
		Name:  "delete",
		Args:  "TENANT",
		Short: "Delete a tenant once nothing of it is left (system administrator)",
		Long: `Delete a tenant. New work in the tenant stops at once. The tenant is
removed when everything it owns (apps, networks, registries, volumes and
backups) has been removed and its servers have reported it closed; until
then the command lists what remains and waits. Nothing is deleted for you:
remove the remaining resources with their own commands. With --no-wait, or
when interrupted, run 'sfcli op resume ID' later to finish.`,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.Var(&revision, "if-revision", "start only if the tenant is still at this `revision`")
			fs.BoolVar(&noWait, "no-wait", false, "start the deletion and return without waiting")
		},
		Run: guard(func(c *cli.Context, args []string) error {
			tenant, err := tenantArg(args, "TENANT")
			if err != nil {
				return err
			}
			s, err := openSession(g, c)
			if err != nil {
				return err
			}
			defer s.Close()
			rev, err := revision.Resolve(func() (uint64, error) {
				v, err := readTenant(c, g, s, tenant)
				return v.Revision, err
			})
			if err != nil {
				return err
			}
			fmt.Fprintf(c.Err, "Tenant %s will stop accepting new work and be removed once it owns nothing.\n", tenant)
			if err = g.Prompter(c).Confirm("Delete tenant " + tenant + "?"); err != nil {
				return err
			}
			opID := id.Get()
			if err = g.Record(s, "tenant-delete", "tenant delete "+tenant, opID); err != nil {
				return err
			}
			fmt.Fprintf(c.Err, "Operation %s\n", opID)
			if _, err = g.send(c, s, change{Summary: "tenant delete " + tenant + " (start)", ID: opID + "-begin", Action: "begin-tenant-retirement", Expected: rev, Payload: control.TenantRetirementSelection{Tenant: tenant, Operation: opID}}); err != nil {
				g.settle(opID, cli.Failed, err.Error())
				return err
			}
			if noWait {
				g.settle(opID, cli.Accepted, "started")
				fmt.Fprintf(c.Out, "tenant %s deletion started; finish it with: sfcli op resume %s\n", tenant, opID)
				return nil
			}
			st, detail, err := finishTenantDelete(c, g, s, tenant, opID, true)
			g.settle(opID, st, detail)
			if err != nil {
				return err
			}
			fmt.Fprintln(c.Out, detail)
			return nil
		}),
	}
}

// finishTenantDelete sends finish once nothing remains, polling until then.
// Without wait (op show) it only reports, once, and sends nothing.
func finishTenantDelete(c *cli.Context, g *globals, s *session, tenant, opID string, wait bool) (cli.State, string, error) {
	printed := -1
	for {
		ctx, cancel := g.Deadline(c)
		status, err := s.Client.TenantRetirement(ctx, s.Target, s.Stored.Session, tenant, "")
		cancel()
		if err != nil {
			return cli.Accepted, "", err
		}
		switch status.Tenant.Phase {
		case access.TenantDeleted:
			return cli.Done, "tenant " + tenant + " deleted", nil
		case access.TenantActive:
			return cli.Failed, "the deletion of " + tenant + " did not start", nil
		}
		if status.RemainingCount == 0 && status.Next == "" && status.ClosedOwners == status.OwnerCount {
			if !wait {
				return cli.Accepted, "nothing remains; finish it with 'sfcli op resume " + opID + "'", nil
			}
			_, err = g.send(c, s, change{Summary: "tenant delete " + tenant + " (finish)", ID: opID + "-finish", Action: "finish-tenant-retirement", Expected: status.Tenant.Revision, Payload: control.TenantRetirementSelection{Tenant: tenant, Operation: opID}})
			if err != nil {
				return cli.Accepted, "", err
			}
			return cli.Done, "tenant " + tenant + " deleted", nil
		}
		detail := fmt.Sprintf("%d resources remain, %d of %d servers closed", status.RemainingCount, status.ClosedOwners, status.OwnerCount)
		if status.RemainingCount != printed {
			printed = status.RemainingCount
			fmt.Fprintf(c.Err, "Tenant %s: %s.\n", tenant, detail)
			for _, r := range status.Remaining {
				fmt.Fprintf(c.Err, "  %s %s %s\n", r.Kind, r.ID, r.Node)
			}
		}
		if !wait {
			return cli.Accepted, detail, nil
		}
		select {
		case <-c.Ctx.Done():
			fmt.Fprintf(c.Err, "Stopped waiting. Finish later with: sfcli op resume %s\n", opID)
			return cli.Accepted, detail, cli.ExitError{Code: exitUnknown}
		case <-time.After(3 * time.Second):
		}
	}
}

func init() {
	opKinds["tenant-delete"] = func(g *globals) cli.Handler {
		start := changeHandler(g, nil, false)
		settle := func(c *cli.Context, op cli.Op, resume bool) (cli.State, string, error) {
			tenant, ok := strings.CutPrefix(op.Summary, "tenant delete ")
			if !ok {
				return "", "", errors.New("not a tenant deletion")
			}
			// The start may not have reached the server: settle it first.
			step := op
			step.ID = op.ID + "-begin"
			call := start.Show
			if resume {
				call = start.Resume
			}
			st, detail, err := call(c, step)
			if err != nil || st != cli.Done {
				return st, detail, err
			}
			s, err := openOpSession(g, c, op)
			if err != nil {
				return "", "", err
			}
			defer s.Close()
			return finishTenantDelete(c, g, s, tenant, op.ID, resume)
		}
		return cli.Handler{
			Show:   func(c *cli.Context, op cli.Op) (cli.State, string, error) { return settle(c, op, false) },
			Resume: func(c *cli.Context, op cli.Op) (cli.State, string, error) { return settle(c, op, true) },
		}
	}
}

// guard turns an unknown outcome into exit code 4 with its message.
func guard(run func(c *cli.Context, args []string) error) func(*cli.Context, []string) error {
	return func(c *cli.Context, args []string) error { return unknown(run(c, args)) }
}

func tenantMemberCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "member",
		Short: "Add, change or remove one member of a tenant",
		Sub: []*cli.Command{
			tenantMemberSetCommand(g, false),
			tenantMemberSetCommand(g, true),
		},
	}
}

func tenantMemberSetCommand(g *globals, remove bool) *cli.Command {
	var id cli.IDFlag
	var revision cli.RevisionFlag
	var role string
	name, args, short := "set", "TENANT USER --role manager|viewer", "Add a member or change their role"
	if remove {
		name, args, short = "remove", "TENANT USER", "Remove a member from the tenant"
	}
	return &cli.Command{
		Name:  name,
		Args:  args,
		Short: short,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.Var(&revision, "if-revision", "change only if the membership is still at this `revision` (0: new)")
			if !remove {
				fs.StringVar(&role, "role", "", "`role`: manager (may change the tenant) or viewer (read only)")
			}
		},
		Run: guard(func(c *cli.Context, argv []string) error {
			if len(argv) != 2 || !cli.ValidID(argv[0]) || !cliprofile.ValidUsername(argv[1]) {
				return cli.Usagef("expected %s", args)
			}
			tenant, username := argv[0], argv[1]
			r := access.Role(role)
			if !remove && r != access.Manager && r != access.Viewer {
				return cli.Usagef("--role must be manager or viewer")
			}
			s, err := openSession(g, c)
			if err != nil {
				return err
			}
			defer s.Close()
			v, err := readTenant(c, g, s, tenant)
			if err != nil {
				return err
			}
			var current *access.TenantMember
			for i := range v.Members {
				if v.Members[i].Username == username && !v.Members[i].Implicit {
					current = &v.Members[i]
				}
			}
			m := access.Membership{Tenant: tenant, Role: r, Enabled: !remove}
			if current != nil {
				m.User = current.User
				if remove {
					m.Role = current.Role
				}
			} else if remove {
				return fmt.Errorf("%s is not a member of %s", username, tenant)
			} else {
				ctx, cancel := g.Deadline(c)
				user, err := s.Client.UserCredentials(ctx, s.Target, s.Stored.Session, username)
				cancel()
				if err != nil {
					return err
				}
				m.User = user.ID
			}
			rev, err := revision.Resolve(func() (uint64, error) {
				if current == nil {
					return 0, nil
				}
				return current.Revision, nil
			})
			if err != nil {
				return err
			}
			summary := fmt.Sprintf("tenant member %s %s %s", name, tenant, username)
			if remove {
				fmt.Fprintf(c.Err, "%s will lose access to %s.\n", username, tenant)
				if err = g.Prompter(c).Confirm("Remove the member?"); err != nil {
					return err
				}
			} else {
				summary += " --role " + role
			}
			if _, err = g.send(c, s, change{Summary: summary, ID: id.Get(), Action: "set-membership", Expected: rev, Payload: m}); err != nil {
				return err
			}
			if remove {
				fmt.Fprintf(c.Out, "%s removed from %s\n", username, tenant)
			} else {
				fmt.Fprintf(c.Out, "%s is %s of %s\n", username, role, tenant)
			}
			return nil
		}),
	}
}

// resourcesView is every page of a tenant's resources with the revisions
// a change to them is checked against.
type resourcesView struct {
	Tenant          string                  `json:"tenant"`
	NetworkRevision uint64                  `json:"network_revision"`
	QuotaRevision   uint64                  `json:"quota_revision"`
	Items           []control.ResourceEntry `json:"items"`
}

// readResourceView reads every page of a tenant's resources ("" = the
// cluster-wide view of a system administrator).
func readResourceView(c *cli.Context, g *globals, s *session, tenant string) (resourcesView, error) {
	v := resourcesView{Tenant: tenant, Items: []control.ResourceEntry{}}
	after := ""
	for {
		ctx, cancel := g.Deadline(c)
		reply, err := s.Client.Resources(ctx, s.Target, s.Stored.Session, userauth.ResourcesQuery{Tenant: tenant, After: after})
		cancel()
		if err != nil {
			return v, err
		}
		if after == "" {
			v.NetworkRevision, v.QuotaRevision = reply.NetworkRevision, reply.QuotaRevision
		} else if reply.NetworkRevision != v.NetworkRevision || reply.QuotaRevision != v.QuotaRevision {
			return v, errors.New("resources changed while reading them; try again")
		}
		v.Items = append(v.Items, reply.Items...)
		if reply.Next == "" {
			return v, nil
		}
		after = reply.Next
	}
}

// readResources is readResourceView's rows and Networks revision.
func readResources(c *cli.Context, g *globals, s *session, tenant string) ([]control.ResourceEntry, uint64, error) {
	v, err := readResourceView(c, g, s, tenant)
	if err != nil {
		return nil, 0, err
	}
	return v.Items, v.NetworkRevision, nil
}

func tenantResourcesCommand(g *globals) *cli.Command {
	var all bool
	return &cli.Command{
		Name:  "resources",
		Args:  "[TENANT]",
		Short: "List a tenant's limits, networks and routes (--all: every tenant)",
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&all, "all", false, "every tenant and the node-wide limits (system administrator)")
		},
		Run: guard(func(c *cli.Context, args []string) error {
			if len(args) > 1 {
				return cli.Usagef("expected [TENANT]")
			}
			s, err := openSession(g, c)
			if err != nil {
				return err
			}
			defer s.Close()
			tenant := ""
			if len(args) == 1 {
				if tenant, err = tenantArg(args, "TENANT"); err != nil {
					return err
				}
			} else if !all {
				if tenant, err = g.Tenant(s, true); err != nil {
					return err
				}
			}
			view, err := readResourceView(c, g, s, tenant)
			if err != nil {
				return err
			}
			rows := view.Items
			return cli.Print(c.Out, g.output.Format(), view, func() cli.Rows {
				r := cli.Rows{Header: []string{"kind", "name", "detail"}}
				for _, e := range rows {
					switch {
					case e.Limit != nil:
						r.Add("limit", e.Limit.Tenant+"@"+e.Limit.Node, fmt.Sprintf("cpu %s, memory %s", cores(e.Limit.Capacity.CPU), cli.Size(e.Limit.Capacity.Memory)))
					case e.Network != nil:
						r.Add("network", memberName(*e.Network), poolText(*e.Network))
					case e.Route != nil:
						r.Add("route", e.Route.ID, string(e.Route.Phase))
					case e.Reservation != nil:
						r.Add("reservation", e.Key, "")
					case e.System != nil:
						r.Add("system-network", tenancy.SystemNetwork, network.SystemRange.String())
					}
				}
				return r
			})
		}),
	}
}

func cores(cpu uint64) string {
	return fmt.Sprintf("%g", float64(cpu)/cpuUnit)
}

func tenantQuotaCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "quota",
		Short: "Limit what a tenant may use on a server",
		Sub:   []*cli.Command{tenantQuotaSetCommand(g)},
	}
}

func tenantQuotaSetCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var revision cli.RevisionFlag
	var cpu float64
	var memory cli.Size
	var consumers, packets int
	var packetBytes cli.Size
	return &cli.Command{
		Name:  "set",
		Args:  "TENANT NODE --cpu N --memory SIZE [--consumers N] [--packet-queue N --packet-queue-bytes SIZE]",
		Short: "Set a tenant's CPU and memory limit on a server (system administrator)",
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.Var(&revision, "if-revision", "change only if the limit is still at this `revision` (0: new)")
			fs.Float64Var(&cpu, "cpu", 0, "CPU cores (decimals allowed)")
			fs.Var(&memory, "memory", "memory `size`, such as 4GiB")
			fs.IntVar(&consumers, "consumers", 0, "containers that may join a managed network or DNS (default: keep, or the server's for a new limit)")
			fs.IntVar(&packets, "packet-queue", 0, "packets queued per TUN network (default: keep, or the server's for a new limit)")
			fs.Var(&packetBytes, "packet-queue-bytes", "`size` queued per TUN network (default: keep, or the server's for a new limit)")
		},
		Run: guard(func(c *cli.Context, args []string) error {
			if len(args) != 2 || !cli.ValidID(args[0]) || !cliprofile.ValidKeyName(args[1]) {
				return cli.Usagef("expected TENANT NODE")
			}
			if !c.Set("cpu") || !c.Set("memory") {
				return cli.Usagef("give --cpu and --memory")
			}
			if math.IsNaN(cpu) || cpu < 0 || cpu > 1e6 {
				return cli.Usagef("--cpu must be 0 or more cores")
			}
			tenant, node := args[0], args[1]
			s, err := openSession(g, c)
			if err != nil {
				return err
			}
			defer s.Close()
			limits := func(scope string) (map[string]tenancy.NodeLimit, error) {
				rows, _, err := readResources(c, g, s, scope)
				out := map[string]tenancy.NodeLimit{}
				for _, e := range rows {
					if e.Limit != nil && e.Limit.Tenant == scope {
						out[e.Limit.Node] = *e.Limit
					}
				}
				return out, err
			}
			global, err := limits("")
			if err != nil {
				return err
			}
			ceiling, ok := global[node]
			if !ok {
				return fmt.Errorf("server %s has no node-wide limit to stay under", node)
			}
			want := uint64(math.Round(cpu * cpuUnit))
			if want > ceiling.Capacity.CPU || uint64(memory) > ceiling.Capacity.Memory {
				return fmt.Errorf("the limit must stay within the server's own: cpu %s, memory %s", cores(ceiling.Capacity.CPU), cli.Size(ceiling.Capacity.Memory))
			}
			mine, err := limits(tenant)
			if err != nil {
				return err
			}
			base, exists := mine[node]
			if !exists {
				base = ceiling
			}
			v := tenancy.NodeLimit{Tenant: tenant, Node: node, Capacity: workload.Resources{CPU: want, Memory: uint64(memory)},
				Networks:              min(base.Networks, ceiling.Networks),
				MaxConsumers:          min(base.MaxConsumers, ceiling.MaxConsumers),
				PacketQueuePackets:    min(base.PacketQueuePackets, ceiling.PacketQueuePackets),
				PacketQueueBytes:      min(base.PacketQueueBytes, ceiling.PacketQueueBytes),
				MaxIngressInstances:   min(base.MaxIngressInstances, ceiling.MaxIngressInstances),
				MaxIngressListeners:   min(base.MaxIngressListeners, ceiling.MaxIngressListeners),
				MaxIngressRequests:    min(base.MaxIngressRequests, ceiling.MaxIngressRequests),
				MaxIngressConnections: min(base.MaxIngressConnections, ceiling.MaxIngressConnections),
				IngressBufferBytes:    min(base.IngressBufferBytes, ceiling.IngressBufferBytes),
			}
			if c.Set("consumers") {
				if consumers < 0 || consumers > ceiling.MaxConsumers {
					return fmt.Errorf("--consumers must be between 0 and the server's own %d", ceiling.MaxConsumers)
				}
				v.MaxConsumers = consumers
			}
			if c.Set("packet-queue") != c.Set("packet-queue-bytes") {
				return cli.Usagef("give --packet-queue and --packet-queue-bytes together")
			}
			if c.Set("packet-queue") {
				if packets < 0 || packets > ceiling.PacketQueuePackets || int64(packetBytes) < 0 || int64(packetBytes) > int64(ceiling.PacketQueueBytes) || (packets == 0) != (packetBytes == 0) {
					return fmt.Errorf("--packet-queue and --packet-queue-bytes must both be 0, or within the server's own %d packets and %s", ceiling.PacketQueuePackets, cli.Size(ceiling.PacketQueueBytes))
				}
				v.PacketQueuePackets, v.PacketQueueBytes = packets, int(packetBytes)
			}
			if v.PacketQueuePackets == 0 || v.PacketQueueBytes == 0 {
				v.PacketQueuePackets, v.PacketQueueBytes = 0, 0
			}
			rev, err := revision.Resolve(func() (uint64, error) {
				if !exists {
					return 0, nil
				}
				return base.Revision, nil
			})
			if err != nil {
				return err
			}
			if exists {
				fmt.Fprintf(c.Err, "%s on %s: cpu %s -> %s, memory %s -> %s\n", tenant, node, cores(base.Capacity.CPU), cores(want), cli.Size(base.Capacity.Memory), memory)
			} else {
				fmt.Fprintf(c.Err, "%s on %s: cpu %s, memory %s (new limit)\n", tenant, node, cores(want), memory)
			}
			if err = g.Prompter(c).Confirm("Set the limit?"); err != nil {
				return err
			}
			summary := fmt.Sprintf("tenant quota set %s %s --cpu %g --memory %s", tenant, node, cpu, memory)
			if _, err = g.send(c, s, change{Summary: summary, ID: id.Get(), Action: "set-node-quota", Expected: rev, Payload: v}); err != nil {
				return err
			}
			fmt.Fprintf(c.Out, "limit of %s on %s set\n", tenant, node)
			return nil
		}),
	}
}
