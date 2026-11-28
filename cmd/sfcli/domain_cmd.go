// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/jay94ks/seafield/internal/certstore"
	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/cluster/control"
)

// sfcli domain: the cluster's registered domains (system administrators).
// Certificates link only to hosts inside one. Usage: docs/cli/domain.md.

func domainCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "domain",
		Short: "Manage the cluster's registered domains",
		Long: `A registered domain covers its name and every name below it. Certificates
are linked only to hosts inside a registered domain. A domain is owned by
one tenant, whose apps open route hosts under it, or is cluster-level (no
owner). Only system administrators can change the list; a tenant user can
list the tenant's own domains with --tenant.`,
		Sub: []*cli.Command{
			domainListCommand(g),
			domainChangeCommand(g, "add", "Register a domain"),
			domainAssignCommand(g),
			domainRequestsCommand(g),
			domainCertificatesCommand(g),
			domainChangeCommand(g, "remove", "Remove a domain; certificates under it lose their links"),
			domainResponderCommand(g),
		},
	}
}

type domainRow struct {
	Name    string `json:"name"`
	Unicode string `json:"unicode,omitempty"`
	Tenant  string `json:"tenant,omitempty"`
	// TenantDeleted: Tenant no longer exists, so the domain counts as
	// cluster-level until it is assigned again.
	TenantDeleted bool   `json:"tenant_deleted,omitempty"`
	AddedBy       string `json:"added_by"`
	AddedAt       string `json:"added_at"`
	at            int64
}

// domainList reads the domain list and the catalog revision it belongs to.
func domainList(c *cli.Context, g *globals, s *session) ([]certstore.Domain, uint64, error) {
	ctx, cancel := g.Deadline(c)
	defer cancel()
	page, err := s.Client.QueryCertificates(ctx, s.Target, s.Stored.Session, control.CertificateQuery{})
	if err != nil {
		return nil, 0, err
	}
	return page.Domains, page.Revision, nil
}

func domainListCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "list",
		Short: "List registered domains (--tenant T: only the domains T owns)",
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			// Only an explicit --tenant narrows the list; the context's
			// default tenant does not.
			tenant := g.tenant
			if len(args) != 0 {
				return cli.Usagef("list takes no arguments")
			}
			var domains []certstore.Domain
			var deleted []string
			if tenant != "" {
				if !cli.ValidID(tenant) {
					return cli.Usagef("invalid tenant %q", tenant)
				}
				ctx, cancel := g.Deadline(c)
				defer cancel()
				reply, err := s.Client.QueryTenantDomains(ctx, s.Target, s.Stored.Session, tenant)
				if err != nil {
					return err
				}
				domains = reply.Domains
			} else {
				ctx, cancel := g.Deadline(c)
				defer cancel()
				page, err := s.Client.QueryCertificates(ctx, s.Target, s.Stored.Session, control.CertificateQuery{})
				if err != nil {
					return err
				}
				domains, deleted = page.Domains, page.DeletedOwners
			}
			rows := []domainRow{}
			for _, d := range domains {
				r := domainRow{Name: d.Name, Tenant: d.Tenant, TenantDeleted: d.Tenant != "" && slices.Contains(deleted, d.Tenant), AddedBy: d.AddedBy, AddedAt: time.Unix(d.AddedAt, 0).UTC().Format(time.RFC3339), at: d.AddedAt}
				if u := certstore.DisplayDomain(d.Name); u != d.Name {
					r.Unicode = u
				}
				rows = append(rows, r)
			}
			return cli.Print(c.Out, g.output.Format(), rows, func() cli.Rows {
				t := cli.Rows{Header: []string{"domain", "unicode", "owner", "added by", "added"}}
				for _, r := range rows {
					owner := r.Tenant
					if owner == "" {
						owner = "(cluster)"
					} else if r.TenantDeleted {
						owner = "(cluster; deleted tenant " + owner + ")"
					}
					t.Add(r.Name, r.Unicode, owner, r.AddedBy, time.Unix(r.at, 0).Local().Format("2006-01-02"))
				}
				return t
			})
		}),
	}
}

func domainChangeCommand(g *globals, verb, short string) *cli.Command {
	var id cli.IDFlag
	var revision cli.RevisionFlag
	return &cli.Command{
		Name:  verb,
		Args:  "DOMAIN",
		Short: short,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.Var(&revision, "if-revision", "only if the certificate store is still at this `revision`")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			// add: an explicit --tenant names the owner (the context's
			// default tenant never does); without it the domain is
			// cluster-level. remove refuses --tenant.
			tenant := g.tenant
			if verb != "add" && tenant != "" {
				return cli.Usagef("remove takes no --tenant")
			}
			if len(args) != 1 {
				return cli.Usagef("%s needs one domain", verb)
			}
			if tenant != "" && !cli.ValidID(tenant) {
				return cli.Usagef("invalid tenant %q", tenant)
			}
			name, ok := certstore.NormalizeDomain(args[0])
			if !ok {
				return cli.Usagef("%q is not a registrable domain or IP address (no wildcard, single label or public suffix such as co.kr)", args[0])
			}
			domains, current, err := domainList(c, g, s)
			if err != nil {
				return err
			}
			_, exists := certstore.Catalog{Domains: domains}.Domain(name)
			if verb == "add" && exists {
				return fmt.Errorf("domain %s is already registered", name)
			}
			if verb == "remove" && !exists {
				return errors.New("domain " + name + " is not registered")
			}
			expected, _ := revision.Resolve(func() (uint64, error) { return current, nil })
			shown := name
			if u := certstore.DisplayDomain(name); u != name {
				shown += " (" + u + ")"
			}
			impact := fmt.Sprintf("Register cluster-level domain %s. Certificates can then link to hosts under it; a tenant's route host under it waits for approval.", shown)
			if tenant != "" {
				impact = fmt.Sprintf("Register domain %s owned by tenant %s. Its apps open route hosts under it, and certificates can link to them.", shown, tenant)
			}
			if _, err := netip.ParseAddr(name); err == nil {
				impact = fmt.Sprintf("Register IP address %s. Certificates with this IP in their SANs can then link to it.", name)
			}
			if verb == "remove" {
				impact = fmt.Sprintf("Remove domain %s. Certificates lose their links to hosts under it, and a certificate left with none moves to unlinked.", shown)
			}
			return g.sendAndPrint(c, s, impact, change{ID: id.Get(), Summary: "domain " + verb + " " + name, Action: verb + "-domain", Expected: expected, Payload: control.DomainChange{Name: name, Tenant: tenant}})
		}),
	}
}

// domainAssignCommand changes a registered domain's owner.
func domainAssignCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var revision cli.RevisionFlag
	var cluster bool
	return &cli.Command{
		Name:  "assign",
		Args:  "DOMAIN (--tenant TENANT | --cluster)",
		Short: "Give a domain to a tenant, or make it cluster-level",
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.Var(&revision, "if-revision", "only if the certificate store is still at this `revision`")
			fs.BoolVar(&cluster, "cluster", false, "make the domain cluster-level (no owner)")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			tenant := g.tenant // explicit --tenant only, as on add
			if len(args) != 1 {
				return cli.Usagef("assign needs one domain")
			}
			if (tenant == "") == !cluster {
				return cli.Usagef("assign needs exactly one of --tenant or --cluster")
			}
			if tenant != "" && !cli.ValidID(tenant) {
				return cli.Usagef("invalid tenant %q", tenant)
			}
			name, ok := certstore.NormalizeDomain(args[0])
			if !ok {
				return cli.Usagef("%q is not a registrable domain or IP address", args[0])
			}
			domains, current, err := domainList(c, g, s)
			if err != nil {
				return err
			}
			d, exists := certstore.Catalog{Domains: domains}.Domain(name)
			if !exists {
				return errors.New("domain " + name + " is not registered")
			}
			if d.Tenant == tenant {
				return fmt.Errorf("domain %s already has that owner", name)
			}
			expected, _ := revision.Resolve(func() (uint64, error) { return current, nil })
			impact := fmt.Sprintf("Make domain %s cluster-level. Tenant route hosts under it then wait for approval.", name)
			if tenant != "" {
				impact = fmt.Sprintf("Give domain %s to tenant %s. Its apps then open route hosts under it.", name, tenant)
			}
			owner := tenant
			if owner == "" {
				owner = "cluster"
			}
			return g.sendAndPrint(c, s, impact, change{ID: id.Get(), Summary: "domain assign " + name + " " + owner, Action: "assign-domain", Expected: expected, Payload: control.DomainChange{Name: name, Tenant: tenant}})
		}),
	}
}

// domainResponderCommand: the cluster's ACME HTTP-01 responder address.
// sfc-web fills it at start from its -acme-listen address.
func domainResponderCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "acme-responder",
		Short: "Show or set where ingress forwards ACME HTTP-01 challenges",
		Long: `Ingress forwards /.well-known/acme-challenge/ of registered-domain hosts on
its plain HTTP listeners to this IP:port (the web app's ACME responder).
Without one that path answers 404. sfc-web sets it itself when it starts.`,
		Sub: []*cli.Command{
			{
				Name:  "show",
				Short: "Show the responder address",
				Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
					if len(args) != 0 {
						return cli.Usagef("show takes no arguments")
					}
					ctx, cancel := g.Deadline(c)
					defer cancel()
					page, err := s.Client.QueryCertificates(ctx, s.Target, s.Stored.Session, control.CertificateQuery{})
					if err != nil {
						return err
					}
					type row struct {
						Address string `json:"address,omitempty"`
						SetBy   string `json:"set_by,omitempty"`
						SetAt   string `json:"set_at,omitempty"`
					}
					var out row
					if r := page.ACMEResponder; r != nil {
						out = row{r.Address, r.SetBy, time.Unix(r.SetAt, 0).UTC().Format(time.RFC3339)}
					}
					return cli.Print(c.Out, g.output.Format(), out, func() cli.Rows {
						t := cli.Rows{Header: []string{"address", "set by", "set"}}
						if out.Address == "" {
							t.Add("(none)", "", "")
						} else {
							t.Add(out.Address, out.SetBy, out.SetAt)
						}
						return t
					})
				}),
			},
			domainResponderChange(g, "set", "Set the responder IP:port"),
			domainResponderChange(g, "clear", "Clear the responder; the challenge path answers 404"),
		},
	}
}

func domainResponderChange(g *globals, verb, short string) *cli.Command {
	var id cli.IDFlag
	var revision cli.RevisionFlag
	args := ""
	if verb == "set" {
		args = "IP:PORT"
	}
	return &cli.Command{
		Name:  verb,
		Args:  args,
		Short: short,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.Var(&revision, "if-revision", "only if the certificate store is still at this `revision`")
		},
		Run: g.withSession(func(c *cli.Context, s *session, a []string) error {
			address := ""
			if verb == "set" {
				if len(a) != 1 {
					return cli.Usagef("set needs one IP:PORT")
				}
				n, ok := certstore.NormalizeResponder(a[0])
				if !ok {
					return cli.Usagef("%q is not an IP:PORT the responder can use (no host name, port 0, zone, 0.0.0.0 or multicast)", a[0])
				}
				address = n
			} else if len(a) != 0 {
				return cli.Usagef("clear takes no arguments")
			}
			_, current, err := domainList(c, g, s)
			if err != nil {
				return err
			}
			expected, _ := revision.Resolve(func() (uint64, error) { return current, nil })
			impact := fmt.Sprintf("Ingress will forward ACME HTTP-01 challenges of registered domains to %s.", address)
			if address == "" {
				impact = "Ingress will stop forwarding ACME HTTP-01 challenges; that path answers 404."
			}
			return g.sendAndPrint(c, s, impact, change{ID: id.Get(), Summary: "acme-responder " + verb + " " + address, Action: "set-acme-responder", Expected: expected, Payload: control.ACMEResponderChange{Address: address}})
		}),
	}
}

// domainRequestsCommand: tenant route hosts under cluster-level domains,
// waiting for (or decided by) a system administrator.
func domainRequestsCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "requests",
		Short: "Tenant route hosts under cluster-level domains, and their approval",
		Long: `A tenant app may route a host under a cluster-level domain; the deploy goes
on, and the host opens only after a system administrator approves it for
that tenant. One host is approved to one tenant. revoke drops a decision:
an approved host waits again.`,
		Sub: []*cli.Command{
			domainRequestsListCommand(g),
			domainDecisionCommand(g, "approve", "Approve a waiting host for a tenant"),
			domainDecisionCommand(g, "deny", "Deny a host for a tenant"),
			domainDecisionCommand(g, "revoke", "Drop the decision on a host"),
		},
	}
}

type hostRequestRow struct {
	Tenant    string   `json:"tenant"`
	Host      string   `json:"host"`
	State     string   `json:"state"`
	Apps      []string `json:"apps,omitempty"`
	DecidedBy string   `json:"decided_by,omitempty"`
	DecidedAt string   `json:"decided_at,omitempty"`
}

func domainRequestsListCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "list",
		Short: "List host requests (--tenant T: that tenant's only)",
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 0 {
				return cli.Usagef("list takes no arguments")
			}
			tenant := g.tenant // explicit --tenant only
			if tenant != "" && !cli.ValidID(tenant) {
				return cli.Usagef("invalid tenant %q", tenant)
			}
			ctx, cancel := g.Deadline(c)
			defer cancel()
			reply, err := s.Client.QueryHostRequests(ctx, s.Target, s.Stored.Session, tenant)
			if err != nil {
				return err
			}
			rows := []hostRequestRow{}
			for _, r := range reply.Requests {
				row := hostRequestRow{Tenant: r.Tenant, Host: r.Host, State: r.State, Apps: r.Apps, DecidedBy: r.DecidedBy}
				if r.DecidedAt > 0 {
					row.DecidedAt = time.Unix(r.DecidedAt, 0).UTC().Format(time.RFC3339)
				}
				rows = append(rows, row)
			}
			return cli.Print(c.Out, g.output.Format(), rows, func() cli.Rows {
				t := cli.Rows{Header: []string{"tenant", "host", "state", "apps", "decided by"}}
				for _, r := range rows {
					t.Add(r.Tenant, r.Host, r.State, strings.Join(r.Apps, ","), r.DecidedBy)
				}
				return t
			})
		}),
	}
}

func domainDecisionCommand(g *globals, verb, short string) *cli.Command {
	var id cli.IDFlag
	var revision cli.RevisionFlag
	return &cli.Command{
		Name:  verb,
		Args:  "TENANT HOST",
		Short: short,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.Var(&revision, "if-revision", "only if the certificate store is still at this `revision`")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 2 {
				return cli.Usagef("%s needs a tenant and a host", verb)
			}
			tenant := args[0]
			if !cli.ValidID(tenant) {
				return cli.Usagef("invalid tenant %q", tenant)
			}
			host, ok := certstore.NormalizeRouteHost(args[1])
			if !ok {
				return cli.Usagef("%q is not a route host", args[1])
			}
			ctx, cancel := g.Deadline(c)
			defer cancel()
			reply, err := s.Client.QueryHostRequests(ctx, s.Target, s.Stored.Session, "")
			if err != nil {
				return err
			}
			expected, _ := revision.Resolve(func() (uint64, error) { return reply.Revision, nil })
			impact := map[string]string{
				"approve": fmt.Sprintf("Approve host %s for tenant %s. Its routes under that host start taking traffic.", host, tenant),
				"deny":    fmt.Sprintf("Deny host %s for tenant %s. Its routes under that host stay closed.", host, tenant),
				"revoke":  fmt.Sprintf("Drop the decision on host %s for tenant %s. An approved host waits again and stops taking traffic.", host, tenant),
			}[verb]
			return g.sendAndPrint(c, s, impact, change{ID: id.Get(), Summary: "domain requests " + verb + " " + tenant + " " + host, Action: verb + "-ingress-host", Expected: expected, Payload: control.HostDecision{Tenant: tenant, Host: host}})
		}),
	}
}

// domainCertificatesCommand: what a tenant user sees of the certificates
// serving its domains and approved hosts (no chain, no key).
func domainCertificatesCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "certificates",
		Short: "Certificates linked to a tenant's hosts (--tenant T)",
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			tenant := g.tenant // explicit --tenant only
			if len(args) != 0 {
				return cli.Usagef("certificates takes no arguments")
			}
			if !cli.ValidID(tenant) {
				return cli.Usagef("certificates needs --tenant")
			}
			ctx, cancel := g.Deadline(c)
			defer cancel()
			reply, err := s.Client.QueryTenantCertificates(ctx, s.Target, s.Stored.Session, tenant)
			if err != nil {
				return err
			}
			rows := reply.Certificates
			if rows == nil {
				rows = []control.TenantCertificate{}
			}
			return cli.Print(c.Out, g.output.Format(), rows, func() cli.Rows {
				t := cli.Rows{Header: []string{"id", "hosts", "issuer", "expires", "state", "links"}}
				for _, r := range rows {
					t.Add(shortID(r.ID), hostsLabel(r.Hosts), r.Issuer, expiresLabel(r.NotAfter), r.State, len(r.Links))
				}
				return t
			})
		}),
	}
}
