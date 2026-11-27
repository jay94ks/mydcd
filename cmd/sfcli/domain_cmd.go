// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"flag"
	"fmt"
	"net/netip"
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
are linked only to hosts inside a registered domain. Only system
administrators can change the list.`,
		Sub: []*cli.Command{
			domainListCommand(g),
			domainChangeCommand(g, "add", "Register a domain"),
			domainChangeCommand(g, "remove", "Remove a domain; certificates under it lose their links"),
			domainResponderCommand(g),
		},
	}
}

type domainRow struct {
	Name    string `json:"name"`
	Unicode string `json:"unicode,omitempty"`
	AddedBy string `json:"added_by"`
	AddedAt string `json:"added_at"`
	at      int64
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
		Short: "List registered domains",
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 0 {
				return cli.Usagef("list takes no arguments")
			}
			domains, _, err := domainList(c, g, s)
			if err != nil {
				return err
			}
			rows := []domainRow{}
			for _, d := range domains {
				r := domainRow{Name: d.Name, AddedBy: d.AddedBy, AddedAt: time.Unix(d.AddedAt, 0).UTC().Format(time.RFC3339), at: d.AddedAt}
				if u := certstore.DisplayDomain(d.Name); u != d.Name {
					r.Unicode = u
				}
				rows = append(rows, r)
			}
			return cli.Print(c.Out, g.output.Format(), rows, func() cli.Rows {
				t := cli.Rows{Header: []string{"domain", "unicode", "added by", "added"}}
				for _, r := range rows {
					t.Add(r.Name, r.Unicode, r.AddedBy, time.Unix(r.at, 0).Local().Format("2006-01-02"))
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
			if len(args) != 1 {
				return cli.Usagef("%s needs one domain", verb)
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
			impact := fmt.Sprintf("Register domain %s. Certificates can then link to hosts under it.", shown)
			if _, err := netip.ParseAddr(name); err == nil {
				impact = fmt.Sprintf("Register IP address %s. Certificates with this IP in their SANs can then link to it.", name)
			}
			if verb == "remove" {
				impact = fmt.Sprintf("Remove domain %s. Certificates lose their links to hosts under it, and a certificate left with none moves to unlinked.", shown)
			}
			return g.sendAndPrint(c, s, impact, change{ID: id.Get(), Summary: "domain " + verb + " " + name, Action: verb + "-domain", Expected: expected, Payload: control.DomainChange{Name: name}})
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
