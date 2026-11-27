// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"cmp"
	"errors"
	"flag"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/internal/vps"
)

// sfcli vps: VPS provider accounts (system administrators). Usage:
// docs/cli/vps.md, design devel/design/vps-nodes.md.

func vpsCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "vps",
		Short: "Manage VPS provider accounts and VPS servers",
		Long: `A provider account lets the cluster create and manage VPS servers with the
provider's API. The secret key is sealed by the voter you are connected to
and is never shown again. Only system administrators can use these commands.`,
		Sub: []*cli.Command{{
			Name:  "account",
			Short: "Provider accounts",
			Sub:   []*cli.Command{vpsAccountListCommand(g), vpsAccountAddCommand(g, false), vpsAccountAddCommand(g, true), vpsAccountSetCommand(g), vpsAccountSSHKeyCommand(g), vpsAccountRemoveCommand(g)},
		}, vpsCatalogCommand(g), vpsListCommand(g), vpsCreateCommand(g), vpsStatusCommand(g), vpsSetCapCommand(g), vpsStopCommand(g), vpsStartCommand(g), vpsDeleteCommand(g)},
	}
}

func vpsAccounts(c *cli.Context, g *globals, s *session) (control.VPSPage, error) {
	ctx, cancel := g.Deadline(c)
	defer cancel()
	return s.Client.QueryVPS(ctx, s.Target, s.Stored.Session, control.VPSQuery{})
}

type vpsAccountRow struct {
	Name            string `json:"name"`
	Vendor          string `json:"vendor"`
	KeyHint         string `json:"key_hint"`
	OverageKRWPerGB int64  `json:"overage_krw_per_gb"`
	SSHPublic       string `json:"ssh_public_key,omitempty"`
	SSHKeyID        string `json:"ssh_key_id,omitempty"`
	UpdatedBy       string `json:"updated_by"`
	UpdatedAt       string `json:"updated_at"`
	at              int64
}

func vpsAccountListCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "list",
		Short: "List provider accounts",
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 0 {
				return cli.Usagef("list takes no arguments")
			}
			page, err := vpsAccounts(c, g, s)
			if err != nil {
				return err
			}
			rows := []vpsAccountRow{}
			for _, a := range page.Accounts {
				rows = append(rows, vpsAccountRow{Name: a.Name, Vendor: a.Vendor, KeyHint: "…" + a.KeyHint, OverageKRWPerGB: a.OverageKRWPerGB, SSHPublic: a.SSHPublic, SSHKeyID: a.SSHKeyID, UpdatedBy: a.UpdatedBy, UpdatedAt: time.Unix(a.UpdatedAt, 0).UTC().Format(time.RFC3339), at: a.UpdatedAt})
			}
			return cli.Print(c.Out, g.output.Format(), rows, func() cli.Rows {
				t := cli.Rows{Header: []string{"name", "vendor", "access key", "traffic KRW/GB", "ssh key", "updated by", "updated"}}
				for _, r := range rows {
					ssh := "registered " + r.SSHKeyID
					if r.SSHKeyID == "" {
						ssh = "not registered"
					}
					t.Add(r.Name, r.Vendor, r.KeyHint, fmt.Sprint(r.OverageKRWPerGB), ssh, r.UpdatedBy, time.Unix(r.at, 0).Local().Format("2006-01-02"))
				}
				return t
			})
		}),
	}
}

// readVPSSecret reads the secret key from --secret-key-file, from standard
// input when it is not a terminal, or from a hidden prompt.
func readVPSSecret(c *cli.Context, file string) ([]byte, error) {
	var raw []byte
	var err error
	switch {
	case file != "":
		raw, err = readSecretFile(file, 257)
	case !stdinTerminal(c):
		raw, err = readLimited(c.In, 257)
	default:
		raw, err = promptHidden(c, "Secret key: ")
	}
	if err != nil {
		return nil, err
	}
	v := bytes.TrimRight(raw, "\r\n")
	if len(v) == 0 || len(v) > 256 || bytes.ContainsAny(v, "\r\n\x00") {
		clear(raw)
		return nil, errors.New("the secret key must be one line of 1 to 256 bytes")
	}
	return v, nil
}

// vpsAccountAddCommand is "add" (a new account) or "rotate-key" (new key
// pair for an existing account).
func vpsAccountAddCommand(g *globals, rotate bool) *cli.Command {
	var id cli.IDFlag
	var vendor, accessKey, secretFile string
	var price int64
	name, short := "add", "Connect a provider account"
	if rotate {
		name, short = "rotate-key", "Replace an account's key pair"
	}
	return &cli.Command{
		Name:  name,
		Args:  "NAME",
		Short: short,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.StringVar(&accessKey, "access-key", "", "the provider's access `KEY`")
			fs.StringVar(&secretFile, "secret-key-file", "", "read the secret key from `FILE` (default: standard input or a prompt)")
			if !rotate {
				fs.StringVar(&vendor, "vendor", "iwinv", "provider (`iwinv`)")
				fs.Int64Var(&price, "traffic-price", 0, "price of traffic above the free allowance, in `KRW` per GB (the provider API does not report it)")
			}
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 1 || !vps.ValidAccountName(args[0]) {
				return cli.Usagef("%s needs one account name (1-32 lower-case letters, digits and hyphens)", name)
			}
			account := args[0]
			if accessKey == "" || len(accessKey) > 256 {
				return cli.Usagef("--access-key is required")
			}
			if _, ok := vps.Lookup(vendor); !rotate && !ok {
				return cli.Usagef("unknown vendor %q", vendor)
			}
			if price < 0 || price > control.MaxOverageKRWPerGB {
				return cli.Usagef("--traffic-price must be 0 to %d", control.MaxOverageKRWPerGB)
			}
			page, err := vpsAccounts(c, g, s)
			if err != nil {
				return err
			}
			old, exists := control.VPSCatalog{Accounts: publicToAccounts(page.Accounts)}.Account(account)
			if !rotate && exists {
				return fmt.Errorf("account %s already exists; use 'sfcli vps account rotate-key' or 'set'", account)
			}
			if rotate {
				if !exists {
					return fmt.Errorf("account %s does not exist", account)
				}
				vendor, price = old.Vendor, old.OverageKRWPerGB
			}
			secret, err := readVPSSecret(c, secretFile)
			if err != nil {
				return err
			}
			defer clear(secret)
			op := id.Get()
			ctx, cancel := g.Deadline(c)
			sealed, err := s.Client.SealVPSCredential(ctx, s.Target, s.Stored.Session, userauth.VPSCredentialInput{Request: op, Account: account, AccessKey: []byte(accessKey), SecretKey: secret})
			cancel()
			if err != nil {
				return fmt.Errorf("the server could not seal the key (connect to a voter server as a system administrator): %w", err)
			}
			impact := fmt.Sprintf("Connect %s account %s. The cluster can then create, stop and delete VPS servers with it.", vendor, account)
			if rotate {
				impact = fmt.Sprintf("Replace the key pair of account %s. The old key is no longer used, and the account gets a new SSH key to register again.", account)
			}
			return g.sendAndPrint(c, s, impact, change{ID: op, Summary: "vps account " + name + " " + account, Action: "put-vps-account", Expected: page.Revision,
				Payload: control.VPSAccountPut{Name: account, Vendor: vendor, OverageKRWPerGB: price, Credential: &sealed, Guard: old.Guard}})
		}),
	}
}

func publicToAccounts(rows []control.VPSPublicAccount) []control.VPSAccount {
	out := make([]control.VPSAccount, 0, len(rows))
	for _, r := range rows {
		out = append(out, control.VPSAccount{Name: r.Name, Vendor: r.Vendor, OverageKRWPerGB: r.OverageKRWPerGB, SSHKeyID: r.SSHKeyID, Guard: r.Guard})
	}
	return out
}

func vpsAccountSetCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var revision cli.RevisionFlag
	var price int64 = -1
	var sshKeyID string
	var sshKeySet bool
	window, average := -1, -1
	pattern := ""
	return &cli.Command{
		Name:  "set",
		Args:  "NAME",
		Short: "Change an account's traffic price or registered SSH key",
		Long: `--ssh-key-id is the provider's ID of the account SSH key ('sfcli vps account
ssh-key NAME' prints the public key to register). Servers created without
--script are installed over SSH with it. "" forgets it.

--guard-window, --guard-average and --guard-pattern tune the early traffic
guard, which stops a server about 15 minutes before its traffic would cross
its cap: the forecast window and the long average in minutes (0 = the
defaults, 5 and 60; the average at least twice the window), and whether
the month's daily pattern is used (on or off).`,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.Var(&revision, "if-revision", "only if the account list is still at this `revision`")
			fs.Int64Var(&price, "traffic-price", -1, "price of traffic above the free allowance, in `KRW` per GB")
			fs.Func("ssh-key-id", "provider `ID` of the registered account SSH key", func(v string) error { sshKeyID, sshKeySet = v, true; return nil })
			fs.IntVar(&window, "guard-window", -1, "early traffic guard window in `minutes` (0 = 5)")
			fs.IntVar(&average, "guard-average", -1, "early traffic guard long average in `minutes` (0 = 60)")
			fs.StringVar(&pattern, "guard-pattern", "", "use the month's daily pattern: `on` or off")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 1 || !vps.ValidAccountName(args[0]) {
				return cli.Usagef("set needs one account name")
			}
			guardSet := window != -1 || average != -1 || pattern != ""
			if price > control.MaxOverageKRWPerGB || price < -1 || price == -1 && !sshKeySet && !guardSet {
				return cli.Usagef("set needs --traffic-price (0 to %d), --ssh-key-id or a --guard-* flag", control.MaxOverageKRWPerGB)
			}
			if pattern != "" && pattern != "on" && pattern != "off" || window < -1 || average < -1 {
				return cli.Usagef("--guard-pattern is on or off, and the guard minutes are 0 or more")
			}
			page, err := vpsAccounts(c, g, s)
			if err != nil {
				return err
			}
			old, exists := control.VPSCatalog{Accounts: publicToAccounts(page.Accounts)}.Account(args[0])
			if !exists {
				return fmt.Errorf("account %s does not exist", args[0])
			}
			expected, _ := revision.Resolve(func() (uint64, error) { return page.Revision, nil })
			if price == -1 {
				price = old.OverageKRWPerGB
			}
			if !sshKeySet {
				sshKeyID = old.SSHKeyID
			}
			guard := old.Guard
			if window != -1 {
				guard.WindowMin = window
			}
			if average != -1 {
				guard.AverageMin = average
			}
			if pattern != "" {
				guard.PatternOff = pattern == "off"
			}
			if !vps.ValidGuard(guard.WindowMin, guard.AverageMin) {
				return cli.Usagef("the guard window is 1 to %d minutes and the average at least twice the window, up to %d", vps.MaxGuardWindowMin, vps.MaxGuardAverageMin)
			}
			impact := fmt.Sprintf("Set account %s: traffic price %d KRW per GB (was %d), SSH key ID %q (was %q), traffic guard %s (was %s).", args[0], price, old.OverageKRWPerGB, sshKeyID, old.SSHKeyID, guardText(guard), guardText(old.Guard))
			return g.sendAndPrint(c, s, impact, change{ID: id.Get(), Summary: "vps account set " + args[0], Action: "put-vps-account", Expected: expected,
				Payload: control.VPSAccountPut{Name: args[0], Vendor: old.Vendor, OverageKRWPerGB: price, SSHKeyID: sshKeyID, Guard: guard}})
		}),
	}
}

func vpsAccountRemoveCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var revision cli.RevisionFlag
	return &cli.Command{
		Name:  "remove",
		Args:  "NAME",
		Short: "Disconnect a provider account",
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.Var(&revision, "if-revision", "only if the account list is still at this `revision`")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 1 || !vps.ValidAccountName(args[0]) {
				return cli.Usagef("remove needs one account name")
			}
			page, err := vpsAccounts(c, g, s)
			if err != nil {
				return err
			}
			if _, exists := (control.VPSCatalog{Accounts: publicToAccounts(page.Accounts)}).Account(args[0]); !exists {
				return fmt.Errorf("account %s does not exist", args[0])
			}
			expected, _ := revision.Resolve(func() (uint64, error) { return page.Revision, nil })
			impact := fmt.Sprintf("Disconnect account %s and forget its sealed key.", args[0])
			return g.sendAndPrint(c, s, impact, change{ID: id.Get(), Summary: "vps account remove " + args[0], Action: "remove-vps-account", Expected: expected,
				Payload: control.VPSAccountSelection{Name: args[0]}})
		}),
	}
}

// vpsCatalogCommand shows what an account's vendor sells now: zones,
// Linux images, instance types with prices, SSH keys and user scripts.
func vpsCatalogCommand(g *globals) *cli.Command {
	var zone, types string
	var minCPU, maxCPU int
	var minMem, maxMem int64
	var all bool
	return &cli.Command{
		Name:  "catalog",
		Args:  "ACCOUNT",
		Short: "Show the zones, images and instance types an account can create",
		Long: `Reads the provider live through the voter you are connected to. Prices
include VAT. Instance types out of stock in a zone are shown as such.`,
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&zone, "zone", "", "only images and types of this `ZONE`")
			fs.StringVar(&types, "core-type", "", "only these core types, comma separated (`SINGLE,MAXIO`)")
			fs.IntVar(&minCPU, "min-vcpu", 0, "at least `N` vCPUs")
			fs.IntVar(&maxCPU, "max-vcpu", 0, "at most `N` vCPUs")
			fs.Int64Var(&minMem, "min-memory", 0, "at least `MiB` of memory")
			fs.Int64Var(&maxMem, "max-memory", 0, "at most `MiB` of memory")
			fs.BoolVar(&all, "all", false, "also show non-Linux images and test types")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 1 || !vps.ValidAccountName(args[0]) {
				return cli.Usagef("catalog needs one account name")
			}
			q := control.VPSOfferQuery{Account: args[0], Zone: zone, Flavors: vps.FlavorQuery{MinVCPU: minCPU, MaxVCPU: maxCPU, MinMemoryMiB: minMem, MaxMemoryMiB: maxMem}}
			if types != "" {
				q.Flavors.CoreTypes = strings.Split(types, ",")
			}
			if !q.Valid() {
				return cli.Usagef("bad --zone, --core-type or size filter")
			}
			ctx, cancel := g.Deadline(c)
			offer, err := s.Client.QueryVPSOffer(ctx, s.Target, s.Stored.Session, q)
			cancel()
			if err != nil {
				return fmt.Errorf("could not read the provider catalogue (connect to a voter server as a system administrator): %w", err)
			}
			if !all {
				offer.Images = slices.DeleteFunc(offer.Images, func(i vps.Image) bool { return !i.Linux })
				offer.Flavors = slices.DeleteFunc(offer.Flavors, func(f vps.Flavor) bool { return f.Provide == vps.ProvideTest })
			}
			return cli.Print(c.Out, g.output.Format(), offer, func() cli.Rows {
				t := cli.Rows{Header: []string{"kind", "id", "name", "detail", "price (KRW, VAT incl.)", "zones"}}
				for _, z := range offer.Zones {
					t.Add("zone", z.ID, z.Name, map[bool]string{true: "", false: "not accepting new servers"}[z.Usable], "", "")
				}
				for _, i := range offer.Images {
					t.Add("image", i.ID, i.Name, i.OS, "", strings.Join(i.Zones, ","))
				}
				for _, f := range offer.Flavors {
					t.Add("type", f.ID, f.Name, vpsFlavorDetail(f), vpsFlavorPrice(f), vpsFlavorZones(f))
				}
				for _, k := range offer.SSHKeys {
					t.Add("ssh-key", k.ID, k.Name, "", "", "")
				}
				for _, sc := range offer.Scripts {
					t.Add("script", sc.ID, sc.Name, "", "", "")
				}
				return t
			})
		}),
	}
}

func vpsFlavorDetail(f vps.Flavor) string {
	d := fmt.Sprintf("%d vCPU, %d MiB, %d GB disk, %g Gbps", f.VCPU, f.MemoryMiB, f.DiskGB, f.NetworkGbps)
	if f.CoreType != "" {
		d = f.CoreType + " " + d
	}
	if f.Provide != "" {
		d += ", " + f.Provide
	}
	if f.GPU != nil {
		d += fmt.Sprintf(", %d× %s %d GB", f.GPU.Count, f.GPU.Model, f.GPU.MemoryGB)
	}
	return d
}

func vpsFlavorPrice(f vps.Flavor) string {
	p := fmt.Sprintf("%d/%s", f.Full.KRW, f.Full.Per)
	if f.Partial != nil {
		p += fmt.Sprintf(" or %d/%s", f.Partial.KRW, f.Partial.Per)
	}
	return p
}

func vpsFlavorZones(f vps.Flavor) string {
	out := make([]string, 0, len(f.Zones))
	for _, z := range f.Zones {
		if z.Available {
			out = append(out, z.ID)
		} else {
			out = append(out, z.ID+" (out of stock)")
		}
	}
	return strings.Join(out, ",")
}

type vpsServerRow struct {
	Name       string `json:"name"`
	Account    string `json:"account"`
	Phase      string `json:"phase"`
	Flavor     string `json:"flavor"`
	CapKRW     int64  `json:"cap_krw"`
	Voter      bool   `json:"voter"`
	InstanceID string `json:"instance_id,omitempty"`
	PublicIP   string `json:"public_ip,omitempty"`
	Failure    string `json:"failure,omitempty"`
	CreatedBy  string `json:"created_by"`
	CreatedAt  string `json:"created_at"`
}

func vpsListCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "list",
		Short: "List VPS servers the cluster created",
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 0 {
				return cli.Usagef("list takes no arguments")
			}
			page, err := vpsAccounts(c, g, s)
			if err != nil {
				return err
			}
			rows := []vpsServerRow{}
			for _, v := range page.Servers {
				rows = append(rows, vpsServerRow{Name: v.Name, Account: v.Account, Phase: v.Phase, Flavor: v.Flavor, CapKRW: v.CapKRW, Voter: v.Voter, InstanceID: v.InstanceID,
					PublicIP: v.PublicIP, Failure: v.Failure, CreatedBy: v.CreatedBy, CreatedAt: time.Unix(v.CreatedAt, 0).UTC().Format(time.RFC3339)})
			}
			return cli.Print(c.Out, g.output.Format(), rows, func() cli.Rows {
				t := cli.Rows{Header: []string{"name", "account", "phase", "type", "monthly cap KRW", "voter", "address", "note"}}
				for _, r := range rows {
					t.Add(r.Name, r.Account, r.Phase, r.Flavor, fmt.Sprint(r.CapKRW), fmt.Sprint(r.Voter), r.PublicIP, r.Failure)
				}
				return t
			})
		}),
	}
}

func vpsCreateCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var account, zone, image, flavor, script string
	var keys listFlag
	var capKRW int64
	var capAction string
	var voter bool
	var port uint
	return &cli.Command{
		Name:  "create",
		Args:  "NAME",
		Short: "Create a VPS server and add it to the cluster",
		Long: `The leader creates the server with the provider, which starts billing at
once, then installs sfcd of the leader's version and adds it as a server
named NAME. It joins as a non-voter; --voter promotes it after it joins.
Every 10 minutes the leader reads its traffic. When its projected monthly
charge passes --cap (judged once an hour of readings exists, or at once when
the charge so far already passes it), --cap-action stop (the default) takes
it out of DNS and powers it off 5 minutes later, with no drain: its apps stop
until you move them. --cap-action notify only shows it in 'sfcli vps status'.
See 'sfcli vps catalog ACCOUNT' for zone, image, type, key and script IDs.`,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.StringVar(&account, "account", "", "provider `ACCOUNT`")
			fs.StringVar(&zone, "zone", "", "`ZONE` ID")
			fs.StringVar(&image, "image", "", "Linux `IMAGE` ID")
			fs.StringVar(&flavor, "type", "", "instance `TYPE` ID")
			fs.StringVar(&script, "script", "", "user `SCRIPT` ID that enrolls over the cluster ingress (default: install over SSH)")
			fs.Var(&keys, "ssh-key", "provider SSH key `ID` (repeat, up to 4)")
			fs.Int64Var(&capKRW, "cap", 0, "monthly charge cap in `KRW`")
			fs.StringVar(&capAction, "cap-action", "stop", "over the cap: `stop` (no drain) or notify")
			fs.BoolVar(&voter, "voter", false, "promote to voter after it joins (needs --script)")
			fs.UintVar(&port, "port", 7443, "SFCP `PORT` of the new server")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 1 {
				return cli.Usagef("create needs one server name")
			}
			page, err := vpsAccounts(c, g, s)
			if err != nil {
				return err
			}
			acct, ok := (control.VPSCatalog{Accounts: publicToAccounts(page.Accounts)}).Account(account)
			if !ok {
				return fmt.Errorf("account %s does not exist", account)
			}
			if script == "" && voter {
				return cli.Usagef("--voter needs --script: a server installed over SSH trusts its host key on first contact and never becomes a voter")
			}
			if script == "" {
				// Installed over SSH: the account key must be on the server.
				if acct.SSHKeyID == "" {
					return fmt.Errorf("without --script the server is installed over SSH; register the account SSH key with the provider and run 'sfcli vps account set %s --ssh-key-id ID' first", account)
				}
				keys = append(keys, acct.SSHKeyID)
			}
			action, ok := vpsCapAction(capAction)
			if !ok {
				return cli.Usagef("--cap-action is stop or notify")
			}
			sorted := slices.Clone([]string(keys))
			slices.Sort(sorted)
			q := control.VPSServerCreate{Name: args[0], Account: account, Zone: zone, Image: image, Flavor: flavor, Script: script, SSHKeys: slices.Compact(sorted), CapKRW: capKRW, CapAction: action, Voter: voter, Port: uint16(port)}
			if port == 0 || port > 65535 || !q.Valid() {
				return cli.Usagef("create needs a server name, --account, --zone, --image, --type and --cap (1 to %d KRW); IDs as 'sfcli vps catalog' shows them", control.MaxVPSCapKRW)
			}
			role := "a non-voter"
			if voter {
				role = "a non-voter, then promote it to voter"
			}
			impact := fmt.Sprintf("Create VPS server %s (type %s in %s) with account %s and add it as %s. The provider bills it from now; %s", q.Name, flavor, zone, account, role, vpsCapImpact(capKRW, action))
			return g.sendAndPrint(c, s, impact, change{ID: id.Get(), Summary: "vps create " + q.Name, Action: "create-vps-node", Expected: page.Revision, Payload: q})
		}),
	}
}

func vpsDeleteCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var revision cli.RevisionFlag
	return &cli.Command{
		Name:  "delete",
		Args:  "NAME",
		Short: "Delete a VPS server and its instance",
		Long: `The leader deletes the instance with the provider, which ends billing, and
then forgets the server. This cannot be undone: the server's disk is gone.
A server that joined the cluster must leave it first with 'sfcli node drain
NAME' and 'sfcli node remove NAME'. A server that never joined (failed, or
still creating or installing) is deleted at once.`,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.Var(&revision, "if-revision", "only if the server list is still at this `revision`")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 1 {
				return cli.Usagef("delete needs one server name")
			}
			page, err := vpsAccounts(c, g, s)
			if err != nil {
				return err
			}
			i := slices.IndexFunc(page.Servers, func(v control.VPSServer) bool { return v.Name == args[0] })
			if i < 0 {
				return fmt.Errorf("VPS server %s does not exist", args[0])
			}
			v := page.Servers[i]
			if v.Phase == control.VPSDeleting {
				return fmt.Errorf("VPS server %s is already being deleted", v.Name)
			}
			ctx, cancel := g.Deadline(c)
			nodes, err := readNodes(ctx, s)
			cancel()
			if err != nil {
				return err
			}
			if vpsStillMember(nodes, v.Name) {
				return fmt.Errorf("VPS server %s is in the cluster; run 'sfcli node drain %s' and 'sfcli node remove %s' first", v.Name, v.Name, v.Name)
			}
			expected, _ := revision.Resolve(func() (uint64, error) { return page.Revision, nil })
			impact := fmt.Sprintf("Delete VPS server %s (instance %s, account %s) with the provider. Its disk is deleted and cannot be recovered.", v.Name, cmp.Or(v.InstanceID, "not created yet"), v.Account)
			return g.sendAndPrint(c, s, impact, change{ID: id.Get(), Summary: "vps delete " + v.Name, Action: "delete-vps-node", Expected: expected,
				Payload: control.VPSServerSelection{Name: v.Name}})
		}),
	}
}

func vpsStopCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var revision cli.RevisionFlag
	var wait time.Duration
	return &cli.Command{
		Name:  "stop",
		Args:  "NAME",
		Short: "Power a VPS server off; it stays in the cluster",
		Long: `First run 'sfcli node cordon NAME' and 'sfcli node drain NAME': only a
cordoned server whose latest drain moved every task can be stopped. A voter
can be stopped only if the other voters still survive one more failure.
The server goes to stopping, and after --dns-wait (the records' TTL) the
leader powers the instance off. The provider may still bill a stopped
server.

Taking the server's address off DNS is not automatic yet (the web does it
in a later release): until then remove it from your DNS records yourself
before stopping, and put it back after start.`,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.Var(&revision, "if-revision", "only if the server list is still at this `revision`")
			fs.DurationVar(&wait, "dns-wait", 5*time.Minute, "wait this long after DNS is changed before powering off (up to 1h)")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 1 || wait < 0 || wait > control.MaxVPSDNSWait*time.Second {
				return cli.Usagef("stop needs one server name and a --dns-wait from 0 to 1h")
			}
			v, page, err := vpsServer(c, g, s, args[0])
			if err != nil {
				return err
			}
			if v.Phase != control.VPSRunning {
				return fmt.Errorf("VPS server %s is %s; only a running server can be stopped", v.Name, v.Phase)
			}
			ctx, cancel := g.Deadline(c)
			nodes, err := readNodes(ctx, s)
			cancel()
			if err != nil {
				return err
			}
			if view, ok := nodes.view(v.Name); !ok || !view.Scheduling.Enabled {
				return fmt.Errorf("VPS server %s is not cordoned; run 'sfcli node cordon %s' and 'sfcli node drain %s' first", v.Name, v.Name, v.Name)
			}
			expected, _ := revision.Resolve(func() (uint64, error) { return page.Revision, nil })
			impact := fmt.Sprintf("Power VPS server %s off after %s. It stays a cordoned member of the cluster. sfc-web takes its address off the Seafield Cluster A/AAAA records of the external domains it is linked to during the wait and puts it back when it runs again; other DNS records are yours to change.", v.Name, wait)
			return g.sendAndPrint(c, s, impact, change{ID: id.Get(), Summary: "vps stop " + v.Name, Action: "stop-vps-node", Expected: expected,
				Payload: control.VPSServerStop{Name: v.Name, DNSWaitSeconds: int64(wait / time.Second)}})
		}),
	}
}

func vpsStartCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var revision cli.RevisionFlag
	return &cli.Command{
		Name:  "start",
		Args:  "NAME",
		Short: "Power a stopped VPS server on again",
		Long: `The leader powers the instance on; once it runs the server is running again.
A server stopped for its monthly cap starts only once its cap is above the
projection recorded at the stop ('sfcli vps set-cap'), or in a later month.
Then run 'sfcli node uncordon NAME' to let work back onto it, and put its
address back into your DNS records (not automatic yet).`,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.Var(&revision, "if-revision", "only if the server list is still at this `revision`")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 1 {
				return cli.Usagef("start needs one server name")
			}
			v, page, err := vpsServer(c, g, s, args[0])
			if err != nil {
				return err
			}
			if v.Phase == control.VPSCapped && !v.CapStop.Cleared(time.Now().Unix(), v.CapKRW) {
				return fmt.Errorf("VPS server %s was stopped for its monthly cap (%d KRW; projected %d KRW for %s). Raise the cap above the projection with 'sfcli vps set-cap %s --cap KRW' first, or wait for next month", v.Name, v.CapStop.CapKRW, v.CapStop.ProjectedKRW, v.CapStop.Month, v.Name)
			}
			if v.Phase != control.VPSStopped && v.Phase != control.VPSCapped {
				return fmt.Errorf("VPS server %s is %s; only a stopped server can be started", v.Name, v.Phase)
			}
			expected, _ := revision.Resolve(func() (uint64, error) { return page.Revision, nil })
			impact := fmt.Sprintf("Power VPS server %s on again.", v.Name)
			return g.sendAndPrint(c, s, impact, change{ID: id.Get(), Summary: "vps start " + v.Name, Action: "start-vps-node", Expected: expected,
				Payload: control.VPSServerSelection{Name: v.Name}})
		}),
	}
}

func vpsCapAction(flag string) (string, bool) {
	switch flag {
	case "stop", "":
		return control.VPSCapStopAction, true
	case control.VPSCapNotify:
		return control.VPSCapNotify, true
	}
	return "", false
}

func vpsCapActionName(action string) string {
	if action == control.VPSCapNotify {
		return "notify"
	}
	return "stop"
}

func vpsCapImpact(capKRW int64, action string) string {
	if action == control.VPSCapNotify {
		return fmt.Sprintf("when its projected monthly charge passes %d KRW it keeps running and 'sfcli vps status' shows it.", capKRW)
	}
	return fmt.Sprintf("when its projected monthly charge passes %d KRW the leader takes it out of DNS and powers it off 5 minutes later, without a drain.", capKRW)
}

func vpsSetCapCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var revision cli.RevisionFlag
	var capKRW int64
	var capAction string
	return &cli.Command{
		Name:  "set-cap",
		Args:  "NAME",
		Short: "Change a VPS server's monthly cap and what happens over it",
		Long: `--cap sets the monthly charge cap in KRW. --cap-action stop (the default)
powers the server off over the cap without a drain; notify keeps it running
and only shows it. Raising the cap above the recorded projection lets a
server stopped for its cap start again ('sfcli vps start').`,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.Var(&revision, "if-revision", "only if the server list is still at this `revision`")
			fs.Int64Var(&capKRW, "cap", 0, "monthly charge cap in `KRW` (default: keep)")
			fs.StringVar(&capAction, "cap-action", "", "over the cap: `stop` (no drain) or notify (default: keep)")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 1 {
				return cli.Usagef("set-cap needs one server name")
			}
			v, page, err := vpsServer(c, g, s, args[0])
			if err != nil {
				return err
			}
			q := control.VPSServerCap{Name: v.Name, CapKRW: v.CapKRW, CapAction: v.CapAction}
			if capKRW != 0 {
				q.CapKRW = capKRW
			}
			if capAction != "" {
				action, ok := vpsCapAction(capAction)
				if !ok {
					return cli.Usagef("--cap-action is stop or notify")
				}
				q.CapAction = action
			}
			if q.CapKRW <= 0 || q.CapKRW > control.MaxVPSCapKRW {
				return cli.Usagef("--cap is 1 to %d KRW", control.MaxVPSCapKRW)
			}
			if q == (control.VPSServerCap{Name: v.Name, CapKRW: v.CapKRW, CapAction: v.CapAction}) {
				return cli.Usagef("set-cap needs --cap or --cap-action that changes something")
			}
			expected, _ := revision.Resolve(func() (uint64, error) { return page.Revision, nil })
			impact := fmt.Sprintf("Set VPS server %s's cap to %d KRW (%s): %s", v.Name, q.CapKRW, vpsCapActionName(q.CapAction), vpsCapImpact(q.CapKRW, q.CapAction))
			return g.sendAndPrint(c, s, impact, change{ID: id.Get(), Summary: "vps set-cap " + v.Name, Action: "set-vps-node-cap", Expected: expected, Payload: q})
		}),
	}
}

type vpsStatusRow struct {
	Name            string              `json:"name"`
	Phase           string              `json:"phase"`
	CapKRW          int64               `json:"cap_krw"`
	CapAction       string              `json:"cap_action"`
	SoFarKRW        int64               `json:"so_far_krw"`
	ProjectedKRW    int64               `json:"projected_krw"`
	BaseSoFarKRW    int64               `json:"base_so_far_krw"`
	BaseMonthKRW    int64               `json:"base_month_krw"`
	TrafficSoFarKRW int64               `json:"traffic_so_far_krw"`
	TrafficMonthKRW int64               `json:"traffic_month_krw"`
	UsedGB          float64             `json:"used_gb"`
	ProjectedGB     float64             `json:"projected_gb"`
	RecentMB        int64               `json:"recent_10m_mb"`
	Judgeable       bool                `json:"judgeable"`
	Over            bool                `json:"over_cap"`
	CapBlocked      bool                `json:"cap_blocked,omitempty"`
	UpdatedAt       string              `json:"updated_at,omitempty"`
	Failure         string              `json:"failure,omitempty"`
	CapStop         *control.VPSCapStop `json:"cap_stop,omitempty"`
}

type vpsStatusOutput struct {
	Leader   string                     `json:"leader"`
	Servers  []vpsStatusRow             `json:"servers"`
	Accounts []control.VPSAccountStatus `json:"accounts"`
}

func vpsStatusCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "status",
		Short: "Show this month's cost of each VPS server",
		Long: `The leader reads each running server's traffic every 10 minutes and keeps
the numbers in memory only; after a leader change they start again from the
provider. A projection can stop a server only once an hour of readings
exists ('judgeable'). The account rows compare the provider's live bill with
the sum of our own counts.`,
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 0 {
				return cli.Usagef("status takes no arguments")
			}
			ctx, cancel := g.Deadline(c)
			defer cancel()
			reply, err := s.Client.QueryVPSStatus(ctx, s.Target, s.Stored.Session)
			if err != nil {
				return err
			}
			live := map[string]control.VPSServerStatus{}
			for _, st := range reply.Status.Servers {
				live[st.Name] = st
			}
			out := vpsStatusOutput{Leader: reply.Status.Leader, Servers: []vpsStatusRow{}, Accounts: reply.Status.Accounts}
			for _, v := range reply.Page.Servers {
				row := vpsStatusRow{Name: v.Name, Phase: v.Phase, CapKRW: v.CapKRW, CapAction: vpsCapActionName(v.CapAction), CapStop: v.CapStop}
				if st, ok := live[v.Name]; ok {
					row.SoFarKRW, row.ProjectedKRW, row.BaseSoFarKRW, row.BaseMonthKRW, row.TrafficSoFarKRW, row.TrafficMonthKRW = st.SoFarKRW, st.ProjectedKRW, st.BaseSoFarKRW, st.BaseMonthKRW, st.TrafficSoFarKRW, st.TrafficMonthKRW
					row.UsedGB, row.ProjectedGB, row.RecentMB, row.Judgeable, row.Over, row.CapBlocked, row.Failure = st.UsedGB, st.ProjectedGB, st.RecentMB, st.Judgeable, st.Over, st.CapBlocked, st.Failure
					if st.UpdatedAt != 0 {
						row.UpdatedAt = time.Unix(st.UpdatedAt, 0).UTC().Format(time.RFC3339)
					}
				}
				out.Servers = append(out.Servers, row)
			}
			return cli.Print(c.Out, g.output.Format(), out, func() cli.Rows {
				t := cli.Rows{Header: []string{"name", "phase", "so far KRW", "projected KRW", "cap KRW", "over cap", "traffic GB", "last 10m MB", "updated", "note"}}
				for _, r := range out.Servers {
					note := r.Failure
					switch {
					case r.CapBlocked:
						note = "over the cap; a voter with no failure to spare keeps running"
					case r.Over && r.CapAction == "notify":
						note = "over the cap (notify only)"
					case r.Phase == control.VPSCapped && r.CapStop != nil:
						note = fmt.Sprintf("stopped for the cap at %s (projected %d KRW)", time.Unix(r.CapStop.At, 0).UTC().Format(time.RFC3339), r.CapStop.ProjectedKRW)
					case r.UpdatedAt != "" && !r.Judgeable:
						note = "under an hour of readings"
					}
					t.Add(r.Name, r.Phase, fmt.Sprint(r.SoFarKRW), fmt.Sprint(r.ProjectedKRW), fmt.Sprint(r.CapKRW), fmt.Sprint(r.Over), fmt.Sprintf("%.1f", r.UsedGB), fmt.Sprint(r.RecentMB), r.UpdatedAt, note)
				}
				for _, a := range out.Accounts {
					t.Add("account "+a.Name, "", fmt.Sprint(a.OursKRW), "", "", "", "", "", time.Unix(a.UpdatedAt, 0).UTC().Format(time.RFC3339), fmt.Sprintf("provider bill %d KRW %s", a.BillKRW, a.Failure))
				}
				return t
			})
		}),
	}
}

func vpsServer(c *cli.Context, g *globals, s *session, name string) (control.VPSServer, control.VPSPage, error) {
	page, err := vpsAccounts(c, g, s)
	if err != nil {
		return control.VPSServer{}, page, err
	}
	i := slices.IndexFunc(page.Servers, func(v control.VPSServer) bool { return v.Name == name })
	if i < 0 {
		return control.VPSServer{}, page, fmt.Errorf("VPS server %s does not exist", name)
	}
	return page.Servers[i], page, nil
}

// vpsStillMember mirrors delete-vps-node: a member entry that is more than
// an invitation and was not removed keeps the server.
func vpsStillMember(nodes nodeDirectory, name string) bool {
	e, ok := nodes.entry(name)
	if !ok || e.Phase == membership.Invited {
		return false
	}
	view, ok := nodes.view(name)
	return !ok || view.Node.Phase != lifecycle.Removed && view.Node.Phase != lifecycle.Retired
}

// vpsAccountSSHKeyCommand prints the account SSH public key to register
// with the provider.
func vpsAccountSSHKeyCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "ssh-key",
		Args:  "NAME",
		Short: "Print the account SSH public key to register with the provider",
		Long: `Register the printed key in the provider console, then give its ID with
'sfcli vps account set NAME --ssh-key-id ID'. The private half stays sealed
in the cluster. rotate-key makes a new one.`,
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 1 || !vps.ValidAccountName(args[0]) {
				return cli.Usagef("ssh-key needs one account name")
			}
			page, err := vpsAccounts(c, g, s)
			if err != nil {
				return err
			}
			for _, a := range page.Accounts {
				if a.Name == args[0] {
					if a.SSHPublic == "" {
						return fmt.Errorf("account %s has no SSH key; run 'sfcli vps account rotate-key %s'", a.Name, a.Name)
					}
					return cli.Print(c.Out, g.output.Format(), map[string]string{"ssh_public_key": a.SSHPublic, "ssh_key_id": a.SSHKeyID}, func() cli.Rows {
						t := cli.Rows{Header: []string{"ssh public key"}}
						t.Add(a.SSHPublic)
						return t
					})
				}
			}
			return fmt.Errorf("account %s does not exist", args[0])
		}),
	}
}

// guardText describes an account's early traffic guard settings.
func guardText(g control.VPSGuard) string {
	w, a := g.WindowMin, g.AverageMin
	if w == 0 {
		w = vps.DefaultGuardWindowMin
	}
	if a == 0 {
		a = vps.DefaultGuardAverageMin
	}
	p := "on"
	if g.PatternOff {
		p = "off"
	}
	return fmt.Sprintf("window %d min, average %d min, pattern %s", w, a, p)
}
