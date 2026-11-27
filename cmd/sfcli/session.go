// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"os"
	"time"

	"golang.org/x/term"

	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/cliprofile"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
)

// session is the logged-in connection a new-frame command works with: the
// same client, target peer and stored login the old commands pass around as
// (client, target, stored, home). Group PRs call globals.open and use these
// fields; the context/key/login PR replaces how the profile is found without
// changing this shape.
type session struct {
	Client  userauth.Client
	Target  sfcp.Peer
	Stored  userauth.Stored
	Home    string
	Context string // context name, for the op list
	tenant  string // default tenant of the context
	closers []func()
}

func (s *session) Close() {
	for i := len(s.closers) - 1; i >= 0; i-- {
		s.closers[i]()
	}
	s.closers = nil
}

// Tenant returns the tenant the command works in: --tenant, else the
// context's tenant. With required it fails when neither is set.
func (g *globals) Tenant(s *session, required bool) (string, error) {
	if g.tenant != "" {
		if !cliprofile.ValidKeyName(g.tenant) {
			return "", cli.Usagef("--tenant %q is not a valid tenant name", g.tenant)
		}
		return g.tenant, nil
	}
	if required && s.tenant == "" {
		return "", cli.Usagef("no tenant: pass --tenant NAME or set one on the context")
	}
	return s.tenant, nil
}

func (g *globals) register(fs *flag.FlagSet) {
	fs.Var(&g.output, "o", "output `format`: table, json or yaml")
	fs.StringVar(&g.context, "context", "", "use this `context` instead of the current one")
	fs.StringVar(&g.tenant, "tenant", "", "work in this `tenant` instead of the context's")
	fs.StringVar(&g.user, "user", "", "act as this saved `user`")
	fs.DurationVar(&g.timeout, "timeout", 30*time.Second, "give up waiting for the server after this long")
	fs.BoolVar(&g.yes, "y", false, "do not ask for confirmation")
	// No flag: SFC_NONINTERACTIVE=1 turns prompting off (prompt_terminal_linux.go).
	g.noInput = nonInteractiveEnv()
	fs.StringVar(&g.reason, "reason", "", "reason recorded with the change (up to 512 characters)")
}

// Prompter asks y/N on the terminal unless -y or SFC_NONINTERACTIVE=1.
func (g *globals) Prompter(c *cli.Context) cli.Prompter {
	interactive := term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stderr.Fd()))
	return cli.Prompter{In: c.In, Out: c.Err, Interactive: interactive, Yes: g.yes, NoInput: g.noInput}
}

// Deadline is the context for one request-reply exchange.
func (g *globals) Deadline(c *cli.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(c.Ctx, g.timeout)
}

// Record saves an operation before it is sent, so `sfcli op` can settle it.
func (g *globals) Record(s *session, kind, summary, id string) error {
	x, err := openOps()
	if err != nil {
		return err
	}
	defer x.Close()
	tenant, _ := g.Tenant(s, false)
	return x.Add(cli.Op{ID: id, Kind: kind, Context: s.Context, Tenant: tenant, Summary: summary})
}

// open logs in with the selected context and saved user. The wallet
// password is asked on the terminal; SFC_NONINTERACTIVE=1 makes that an error.
func (g *globals) open(c *cli.Context) (*session, error) {
	if g.timeout <= 0 || g.timeout > 5*time.Minute {
		return nil, cli.Usagef("--timeout must be more than 0 and at most 5m")
	}
	if g.user != "" && !cliprofile.ValidUsername(g.user) {
		return nil, cli.Usagef("--user %q is not a valid user name", g.user)
	}
	if g.context != "" && !cliprofile.ValidName(g.context) {
		return nil, cli.Usagef("--context %q is not a valid context name", g.context)
	}
	var reason *control.OperationReason
	if g.reason != "" {
		reason = &control.OperationReason{Text: g.reason}
		if !reason.Valid() {
			return nil, cli.Usagef("--reason must be at most 512 characters of text")
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	selected, err := resolveCommandProfile(home, g.context, "", "")
	if err != nil {
		return nil, err
	}
	cfg := selected.Client
	clusterID, _ := config.ClusterKey(cfg.Cluster)
	s := &session{Home: home, Context: selected.Context, tenant: selected.Target.Tenant}
	s.Client = userauth.Client{Cluster: clusterID, OperationReason: reason}
	peerID := selected.Target.Peer
	peers := map[sfcp.Identity]sfcp.Peer{}
	for i, p := range cfg.Peers {
		key, _ := identity.ParseKey(p.Key)
		peer := sfcp.Peer{ID: p.ID, Endpoint: p.Endpoint, Policy: sfcp.Policy{Key: sfcp.Identity(key), Respond: true}}
		peers[peer.Key] = peer
		s.Client.Peers = append(s.Client.Peers, peer)
		if p.ID == peerID || peerID == "" && i == 0 {
			s.Target = peer
		}
	}
	if s.Target.ID == "" {
		return nil, errors.New("the context names no reachable server")
	}
	ok := false
	defer func() {
		if !ok {
			s.Close()
		}
	}()
	password, fromEnv, err := walletPasswordFromEnv()
	if err == nil && !fromEnv {
		password, err = readWalletPassword(walletFD{}, g.noInput, "Wallet password", c.Err)
	}
	if err != nil {
		return nil, err
	}
	credentials, err := userauth.OpenCredentials(home, password)
	clear(password)
	if err != nil {
		return nil, err
	}
	s.closers = append(s.closers, func() { credentials.Close() })
	s.Client.Credentials, s.Client.Username = credentials, g.user
	if s.Stored, err = userauth.Load(home, s.Client); err != nil {
		return nil, err
	}
	s.Client.Self, s.Client.Username = s.Stored.Self, s.Stored.Username
	s.closers = append(s.closers, func() { clear(s.Client.Self.Private) })
	if tenant, _ := g.Tenant(s, false); tenant != "" {
		s.Stored.Tenant, s.Stored.TargetTenant = tenant, tenant
	}
	if s.Client.Mesh, err = sfcp.NewTransport(s.Client.Self, clusterID, func(key sfcp.Identity) (sfcp.Peer, bool) { p, ok := peers[key]; return p, ok }); err != nil {
		return nil, err
	}
	s.closers = append(s.closers, func() { s.Client.Mesh.Close() })
	ok = true
	return s, nil
}
