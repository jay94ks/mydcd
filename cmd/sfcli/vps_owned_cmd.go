// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/internal/vps"
)

// sfcli vps owned: VPS servers the operator already owns at a provider
// (Hostinger) and attaches to the cluster. The cluster never buys or
// deletes them, and they are kept apart from the VPS servers the cluster
// creates ('sfcli vps list'). Design devel/design/vps-hostinger.md.

func vpsOwnedCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "owned",
		Short: "Attach VPS servers you already own (Hostinger)",
		Long: `An owned VPS is one you bought and renew yourself at the provider. The
cluster only attaches it: it never buys, renews or deletes it. Renewal and
billing stay in the provider's panel. Owned servers and their accounts are
shown only here, never with the VPS servers the cluster creates.`,
		Sub: []*cli.Command{{
			Name:  "account",
			Short: "Owned-VPS provider accounts",
			Sub:   []*cli.Command{vpsOwnedAccountListCommand(g), vpsOwnedAccountAddCommand(g, false), vpsOwnedAccountAddCommand(g, true), vpsOwnedAccountRemoveCommand(g)},
		}, vpsOwnedListCommand(g), vpsOwnedStatusCommand(g), vpsOwnedAttachCommand(g), vpsOwnedSetCommand(g), vpsOwnedDetachCommand(g)},
	}
}

func ownedVPS(c *cli.Context, g *globals, s *session) (userauth.OwnedVPSReply, error) {
	ctx, cancel := g.Deadline(c)
	defer cancel()
	return s.Client.QueryOwnedVPS(ctx, s.Target, s.Stored.Session, false)
}

func ownedVendors() []string {
	var out []string
	for _, v := range vps.Vendors() {
		if v.Ownership == vps.Owned {
			out = append(out, v.ID)
		}
	}
	return out
}

func vpsOwnedAccountListCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "list",
		Short: "List owned-VPS provider accounts",
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 0 {
				return cli.Usagef("list takes no arguments")
			}
			r, err := ownedVPS(c, g, s)
			if err != nil {
				return err
			}
			rows := []vpsAccountRow{}
			for _, a := range r.Page.Accounts {
				rows = append(rows, vpsAccountRow{Name: a.Name, Vendor: a.Vendor, KeyHint: "…" + a.KeyHint, SSHPublic: a.SSHPublic, UpdatedBy: a.UpdatedBy, UpdatedAt: time.Unix(a.UpdatedAt, 0).UTC().Format(time.RFC3339), at: a.UpdatedAt})
			}
			return cli.Print(c.Out, g.output.Format(), rows, func() cli.Rows {
				t := cli.Rows{Header: []string{"name", "vendor", "token", "updated by", "updated"}}
				for _, r := range rows {
					t.Add(r.Name, r.Vendor, r.KeyHint, r.UpdatedBy, time.Unix(r.at, 0).Local().Format("2006-01-02"))
				}
				return t
			})
		}),
	}
}

// readOwnedToken reads the provider API token from --token-file, from
// standard input when it is not a terminal, or from a hidden prompt.
func readOwnedToken(c *cli.Context, file string) ([]byte, error) {
	var raw []byte
	var err error
	switch {
	case file != "":
		raw, err = readSecretFile(file, 257)
	case !stdinTerminal(c):
		raw, err = readLimited(c.In, 257)
	default:
		raw, err = promptHidden(c, "API token: ")
	}
	if err != nil {
		return nil, err
	}
	v := bytes.TrimRight(raw, "\r\n")
	if len(v) == 0 || len(v) > 256 || bytes.ContainsAny(v, "\r\n\x00") {
		clear(raw)
		return nil, errors.New("the API token must be one line of 1 to 256 bytes")
	}
	return v, nil
}

func vpsOwnedAccountAddCommand(g *globals, rotate bool) *cli.Command {
	var id cli.IDFlag
	var vendor, tokenFile string
	name, short := "add", "Connect an owned-VPS provider account"
	if rotate {
		name, short = "rotate-key", "Replace an owned-VPS account's API token"
	}
	return &cli.Command{
		Name:  name,
		Args:  "NAME",
		Short: short,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.StringVar(&tokenFile, "token-file", "", "read the API token from `FILE` (default: standard input or a prompt)")
			if !rotate {
				fs.StringVar(&vendor, "vendor", "hostinger", "provider (`hostinger`)")
			}
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 1 || !vps.ValidAccountName(args[0]) {
				return cli.Usagef("%s needs one account name (1-32 lower-case letters, digits and hyphens)", name)
			}
			account := args[0]
			if _, ok := vps.LookupOwned(vendor); !rotate && !ok {
				return cli.Usagef("unknown owned-VPS vendor %q (one of %v)", vendor, ownedVendors())
			}
			r, err := ownedVPS(c, g, s)
			if err != nil {
				return err
			}
			i := slices.IndexFunc(r.Page.Accounts, func(a control.VPSPublicAccount) bool { return a.Name == account })
			if !rotate && i >= 0 {
				return fmt.Errorf("account %s already exists; use 'sfcli vps owned account rotate-key'", account)
			}
			if rotate {
				if i < 0 {
					return fmt.Errorf("owned-VPS account %s does not exist", account)
				}
				vendor = r.Page.Accounts[i].Vendor
			}
			token, err := readOwnedToken(c, tokenFile)
			if err != nil {
				return err
			}
			defer clear(token)
			op := id.Get()
			ctx, cancel := g.Deadline(c)
			sealed, err := s.Client.SealVPSCredential(ctx, s.Target, s.Stored.Session, userauth.VPSCredentialInput{Request: op, Account: account, AccessKey: token})
			cancel()
			if err != nil {
				return fmt.Errorf("the server could not seal the token (connect to a voter server as a system administrator): %w", err)
			}
			impact := fmt.Sprintf("Connect %s account %s. The cluster can then read its VPS servers and attach them; it never buys, renews or deletes them.", vendor, account)
			if rotate {
				impact = fmt.Sprintf("Replace the API token of account %s. The account also gets a new SSH key for later SSH installs.", account)
			}
			return g.sendAndPrint(c, s, impact, change{ID: op, Summary: "vps owned account " + name + " " + account, Action: "put-vps-account", Expected: r.AccountRootRevision,
				Payload: control.VPSAccountPut{Name: account, Vendor: vendor, Credential: &sealed}})
		}),
	}
}

func vpsOwnedAccountRemoveCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var revision cli.RevisionFlag
	return &cli.Command{
		Name:  "remove",
		Args:  "NAME",
		Short: "Disconnect an owned-VPS provider account",
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.Var(&revision, "if-revision", "only if the account list is still at this `revision`")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 1 || !vps.ValidAccountName(args[0]) {
				return cli.Usagef("remove needs one account name")
			}
			r, err := ownedVPS(c, g, s)
			if err != nil {
				return err
			}
			if !slices.ContainsFunc(r.Page.Accounts, func(a control.VPSPublicAccount) bool { return a.Name == args[0] }) {
				return fmt.Errorf("owned-VPS account %s does not exist", args[0])
			}
			if slices.ContainsFunc(r.Page.Servers, func(v control.OwnedVPS) bool { return v.Account == args[0] }) {
				return fmt.Errorf("account %s still has attached servers; detach them first with 'sfcli vps owned detach'", args[0])
			}
			expected, _ := revision.Resolve(func() (uint64, error) { return r.AccountRootRevision, nil })
			impact := fmt.Sprintf("Disconnect account %s and forget its sealed token. Its VPS servers stay at the provider.", args[0])
			return g.sendAndPrint(c, s, impact, change{ID: id.Get(), Summary: "vps owned account remove " + args[0], Action: "remove-vps-account", Expected: expected,
				Payload: control.VPSAccountSelection{Name: args[0]}})
		}),
	}
}

type ownedVPSRow struct {
	Name       string `json:"name"`
	Account    string `json:"account"`
	InstanceID string `json:"instance_id"`
	Install    string `json:"install"`
	Voter      bool   `json:"voter"`
	Protect    string `json:"protect"`
	Phase      string `json:"phase"`
	Failure    string `json:"failure,omitempty"`
	Held       bool   `json:"held,omitempty"`
	AttachedBy string `json:"attached_by"`
	AttachedAt string `json:"attached_at"`
}

func vpsOwnedListCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "list",
		Short: "List attached owned VPS servers",
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 0 {
				return cli.Usagef("list takes no arguments")
			}
			r, err := ownedVPS(c, g, s)
			if err != nil {
				return err
			}
			rows := []ownedVPSRow{}
			for _, v := range r.Page.Servers {
				rows = append(rows, ownedVPSRow{Name: v.Name, Account: v.Account, InstanceID: v.InstanceID, Install: v.Install, Voter: v.Voter, Protect: v.Protect, Phase: v.Phase, Failure: v.Failure, Held: v.Limit != nil,
					AttachedBy: v.AttachedBy, AttachedAt: time.Unix(v.AttachedAt, 0).UTC().Format(time.RFC3339)})
			}
			return cli.Print(c.Out, g.output.Format(), rows, func() cli.Rows {
				t := cli.Rows{Header: []string{"name", "account", "instance", "install", "voter", "near limit", "phase", "note"}}
				for _, r := range rows {
					note := r.Failure
					if r.Held {
						note = "traffic held (" + r.Protect + ")"
					}
					t.Add(r.Name, r.Account, r.InstanceID, r.Install, fmt.Sprint(r.Voter), r.Protect, r.Phase, note)
				}
				return t
			})
		}),
	}
}

func ownedProtect(flag string) (string, bool) {
	switch flag {
	case "", control.OwnedProtectExclude:
		return control.OwnedProtectExclude, true
	case control.OwnedProtectLowWeight:
		return control.OwnedProtectLowWeight, true
	}
	return "", false
}

func ownedProtectImpact(protect string) string {
	if protect == control.OwnedProtectLowWeight {
		return "Before its monthly bandwidth runs out, its backends get the lowest weight."
	}
	return "Before its monthly bandwidth runs out, it is taken out of DNS and routing until the month resets."
}

func vpsOwnedAttachCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var account, instance, existing, protect string
	var ssh, voter bool
	var port uint
	return &cli.Command{
		Name:  "attach",
		Args:  "NAME",
		Short: "Attach an owned VPS as server NAME",
		Long: `Attach the provider's VPS --instance of --account as server NAME. Choose how
sfcd gets there:

  --ssh            the leader installs sfcd over SSH with the account's key
                   (the server never votes: its host key is trusted on first use)
  (default)        you run the install command on the VPS
                   (docs/reference/vps-enroll.md "설치 명령")
  --existing NODE  sfcd already runs there and NODE joined; only bind the record

The VPS itself is not changed, bought or renewed.`,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.StringVar(&account, "account", "", "owned-VPS `ACCOUNT`")
			fs.StringVar(&instance, "instance", "", "the provider's VPS `ID`")
			fs.BoolVar(&ssh, "ssh", false, "install sfcd over SSH")
			fs.StringVar(&existing, "existing", "", "bind the joined server `NODE` (NAME must be NODE)")
			fs.BoolVar(&voter, "voter", false, "promote to voter after joining (manual install only)")
			fs.UintVar(&port, "port", 7443, "SFCP `PORT` of the new server (not with --existing)")
			fs.StringVar(&protect, "near-limit", "exclude", "before the monthly bandwidth runs out: `exclude` (leave DNS and routing) or low-weight")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 1 || !lifecycle.ValidID(args[0]) {
				return cli.Usagef("attach needs one server name")
			}
			name := args[0]
			if !vps.ValidAccountName(account) || instance == "" {
				return cli.Usagef("--account and --instance are required")
			}
			mode, ok := ownedProtect(protect)
			if !ok {
				return cli.Usagef("--near-limit must be exclude or low-weight")
			}
			install := control.OwnedInstallManual
			switch {
			case ssh && existing != "":
				return cli.Usagef("--ssh and --existing cannot be used together")
			case ssh:
				install = control.OwnedInstallSSH
			case existing != "":
				if existing != name {
					return cli.Usagef("--existing %s must name the same server as NAME", existing)
				}
				install = control.OwnedInstallExisting
			}
			if port == 0 || port > 65535 {
				return cli.Usagef("--port must be 1 to 65535")
			}
			sfcp := uint16(port)
			if install == control.OwnedInstallExisting {
				sfcp = 0 // the joined server keeps its own endpoint
			}
			if voter && install != control.OwnedInstallManual {
				return cli.Usagef("--voter needs the manual install (an SSH or existing server does not vote from here)")
			}
			r, err := ownedVPS(c, g, s)
			if err != nil {
				return err
			}
			if !slices.ContainsFunc(r.Page.Accounts, func(a control.VPSPublicAccount) bool { return a.Name == account }) {
				return fmt.Errorf("owned-VPS account %s does not exist ('sfcli vps owned account list')", account)
			}
			how := map[string]string{
				control.OwnedInstallSSH: "The leader puts the account's SSH key on the VPS and installs sfcd over SSH.",
				control.OwnedInstallManual: "Once 'sfcli vps owned list' shows it installing with an address, run as root on the VPS within 30 minutes: " +
					`curl -fsS "https://CLUSTER_HOST/.well-known/sfc/node/install.sh?name=` + name + `" | sh` + " (CLUSTER_HOST = the cluster's external address).",
				control.OwnedInstallExisting: "sfcd already runs there; nothing is installed.",
			}[install]
			impact := fmt.Sprintf("Attach VPS %s of account %s as server %s. %s %s The VPS is not bought, renewed or deleted by the cluster.", instance, account, name, how, ownedProtectImpact(mode))
			return g.sendAndPrint(c, s, impact, change{ID: id.Get(), Summary: "vps owned attach " + name, Action: control.AttachOwnedVPSAction, Expected: r.RootRevision,
				Payload: control.OwnedVPSAttach{Name: name, Account: account, InstanceID: instance, Install: install, Voter: voter, Port: sfcp, Protect: mode}})
		}),
	}
}

func vpsOwnedSetCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var revision cli.RevisionFlag
	var protect string
	var restore bool
	return &cli.Command{
		Name:  "set",
		Args:  "NAME",
		Short: "Change what happens before an owned VPS runs out of bandwidth",
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.Var(&revision, "if-revision", "only if the server list is still at this `revision`")
			fs.StringVar(&protect, "near-limit", "", "`exclude` (leave DNS and routing) or low-weight")
			fs.BoolVar(&restore, "restore", false, "end the traffic hold now (not held again this month)")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 1 {
				return cli.Usagef("set needs one server name")
			}
			mode, ok := ownedProtect(protect)
			if !ok || protect == "" && !restore {
				return cli.Usagef("--near-limit must be exclude or low-weight, or use --restore")
			}
			if protect == "" {
				mode = ""
			}
			r, err := ownedVPS(c, g, s)
			if err != nil {
				return err
			}
			i := slices.IndexFunc(r.Page.Servers, func(v control.OwnedVPS) bool { return v.Name == args[0] })
			if i < 0 {
				return fmt.Errorf("owned VPS %s is not attached", args[0])
			}
			if restore && r.Page.Servers[i].Limit == nil {
				return fmt.Errorf("owned VPS %s is not held for traffic", args[0])
			}
			impact := ""
			if mode != "" {
				impact = ownedProtectImpact(mode)
			}
			if restore {
				impact = strings.TrimSpace(impact + " Send user traffic to it again now; the provider may slow it down until the month ends, and it is not held again this month.")
			}
			expected, _ := revision.Resolve(func() (uint64, error) { return r.RootRevision, nil })
			return g.sendAndPrint(c, s, impact, change{ID: id.Get(), Summary: "vps owned set " + args[0], Action: control.SetOwnedVPSAction, Expected: expected,
				Payload: control.OwnedVPSSet{Name: args[0], Protect: mode, Restore: restore}})
		}),
	}
}

func vpsOwnedDetachCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var revision cli.RevisionFlag
	return &cli.Command{
		Name:  "detach",
		Args:  "NAME",
		Short: "Forget an attached owned VPS",
		Long: `Forget the record that binds the provider's VPS to server NAME. The VPS keeps
running and stays yours at the provider; remove or cancel it in the
provider's panel if you no longer need it. A server that joined stays in the
cluster until 'sfcli node drain NAME' and 'sfcli node remove NAME'.`,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.Var(&revision, "if-revision", "only if the server list is still at this `revision`")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 1 {
				return cli.Usagef("detach needs one server name")
			}
			r, err := ownedVPS(c, g, s)
			if err != nil {
				return err
			}
			i := slices.IndexFunc(r.Page.Servers, func(v control.OwnedVPS) bool { return v.Name == args[0] })
			if i < 0 {
				return fmt.Errorf("owned VPS %s is not attached", args[0])
			}
			v := r.Page.Servers[i]
			expected, _ := revision.Resolve(func() (uint64, error) { return r.RootRevision, nil })
			impact := fmt.Sprintf("Forget owned VPS %s (instance %s, account %s). The VPS and its subscription stay at the provider.", v.Name, v.InstanceID, v.Account)
			return g.sendAndPrint(c, s, impact, change{ID: id.Get(), Summary: "vps owned detach " + v.Name, Action: control.DetachOwnedVPSAction, Expected: expected,
				Payload: control.OwnedVPSSelection{Name: v.Name}})
		}),
	}
}

func vpsOwnedStatusCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "status",
		Short: "Show this month's bandwidth and the remaining subscription of owned VPS servers",
		Long: `The leader reads each running owned VPS from the provider every 15 minutes
(bandwidth) and once a day (subscription). Only the remaining period is
shown; renew in the provider's panel.`,
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 0 {
				return cli.Usagef("status takes no arguments")
			}
			ctx, cancel := g.Deadline(c)
			r, err := s.Client.QueryOwnedVPS(ctx, s.Target, s.Stored.Session, true)
			cancel()
			if err != nil {
				return err
			}
			st := control.OwnedVPSStatus{Servers: []control.OwnedVPSServerStatus{}}
			if r.Status != nil {
				st = *r.Status
			}
			held := map[string]string{}
			for _, v := range r.Page.Servers {
				if v.Limit != nil {
					held[v.Name] = "held (" + v.Limit.Mode + ")"
				}
			}
			return cli.Print(c.Out, g.output.Format(), st, func() cli.Rows {
				t := cli.Rows{Header: []string{"name", "bandwidth MB", "runs out", "subscription ends", "renewal", "traffic", "note"}}
				for _, v := range st.Servers {
					out, ends, renew := "-", "-", "-"
					if v.ReachAt > 0 {
						out = time.Unix(v.ReachAt, 0).Local().Format("2006-01-02 15:04")
					}
					if v.ExpiresAt > 0 {
						ends = fmt.Sprintf("%s (%d days)", time.Unix(v.ExpiresAt, 0).Local().Format("2006-01-02"), int(time.Until(time.Unix(v.ExpiresAt, 0)).Hours()/24))
					}
					if v.Currency != "" {
						renew = fmt.Sprintf("%d.%02d %s", v.RenewalCost/100, v.RenewalCost%100, v.Currency)
					}
					t.Add(v.Name, fmt.Sprintf("%d / %d", v.UsedMB, v.MonthMB), out, ends, renew, cmpOr(held[v.Name], "normal"), v.Failure)
				}
				return t
			})
		}),
	}
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
