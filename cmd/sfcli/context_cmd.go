// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"slices"
	"time"

	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/cliprofile"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// discoverNode asks an endpoint which cluster and node it is, without
// trusting the answer. Tests replace it.
var discoverNode = sfcp.Discover

// contextView is one context as `context list/show` print it.
type contextView struct {
	Name    string `json:"name"`
	Current bool   `json:"current"`
	cliprofile.Context
	Nodes []cliprofile.TrustedNode `json:"nodes,omitempty"`
}

func contextCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "context",
		Short: "Choose where to connect, as whom, and in which tenant",
		Long: `A context is one way to reach a cluster: an endpoint, the cluster's ID,
and default user and tenant. Contexts live in ~/.sfc/config.yaml; the node
keys you confirmed live in ~/.sfc/trust/. Neither grants anything on the
server.`,
		Sub: []*cli.Command{
			contextAddCommand(g),
			{
				Name:  "list",
				Short: "List contexts",
				Run: func(c *cli.Context, args []string) error {
					if len(args) != 0 {
						return cli.Usagef("list takes no arguments")
					}
					return withStore(false, func(st *cliprofile.Store) error {
						cfg, err := st.Load()
						if err != nil {
							return err
						}
						views := []contextView{}
						for _, name := range cfg.Names() {
							views = append(views, contextView{Name: name, Current: name == cfg.Current, Context: cfg.Contexts[name]})
						}
						return cli.Print(c.Out, g.output.Format(), views, func() cli.Rows {
							t := cli.Rows{Header: []string{"", "name", "endpoint", "user", "tenant"}}
							for _, v := range views {
								mark := ""
								if v.Current {
									mark = "*"
								}
								t.Add(mark, v.Name, v.Endpoint, v.User, v.Tenant)
							}
							return t
						})
					})
				},
			},
			{
				Name:  "use",
				Args:  "NAME",
				Short: "Make a context the current one",
				Run: func(c *cli.Context, args []string) error {
					name, err := contextName(args)
					if err != nil {
						return err
					}
					return updateConfig(func(cfg *cliprofile.Config) error {
						if _, ok := cfg.Contexts[name]; !ok {
							return fmt.Errorf("%w %q", cliprofile.ErrNotFound, name)
						}
						cfg.Current = name
						fmt.Fprintf(c.Err, "Now using context %s.\n", name)
						return nil
					})
				},
			},
			{
				Name:  "show",
				Args:  "[NAME]",
				Short: "Show a context and the node keys trusted for its cluster",
				Run: func(c *cli.Context, args []string) error {
					if len(args) > 1 {
						return cli.Usagef("show takes at most one context name")
					}
					name := g.context
					if len(args) == 1 {
						name = args[0]
					}
					return withStore(false, func(st *cliprofile.Store) error {
						cfg, err := st.Load()
						if err != nil {
							return err
						}
						if name == "" {
							name = cfg.Current
						}
						if name == "" {
							return cliprofile.ErrNoContext
						}
						ctx, ok := cfg.Contexts[name]
						if !ok {
							return fmt.Errorf("%w %q", cliprofile.ErrNotFound, name)
						}
						trust, err := st.Trust(ctx.Cluster)
						if err != nil {
							return err
						}
						v := contextView{Name: name, Current: name == cfg.Current, Context: ctx, Nodes: trust.Nodes}
						return cli.Print(c.Out, g.output.Format(), v, func() cli.Rows {
							t := cli.Rows{Header: []string{"field", "value"}}
							t.Add("name", v.Name)
							t.Add("endpoint", v.Endpoint)
							t.Add("cluster", v.Cluster)
							t.Add("user", v.User)
							t.Add("tenant", v.Tenant)
							t.Add("wallet key", v.Key)
							for _, n := range v.Nodes {
								t.Add("node "+n.ID, fingerprint(n.Key)+" "+fmt.Sprint(n.Endpoints))
							}
							return t
						})
					})
				},
			},
			contextSetCommand(g),
			{
				Name:  "remove",
				Args:  "NAME",
				Short: "Forget a context",
				Long:  "Removes the context from this computer. Saved logins and operations stay; nothing changes on the server.",
				Run: func(c *cli.Context, args []string) error {
					name, err := contextName(args)
					if err != nil {
						return err
					}
					return withStore(false, func(st *cliprofile.Store) error {
						unlock, err := st.Lock()
						if err != nil {
							return err
						}
						defer unlock()
						cfg, err := st.Load()
						if err != nil {
							return err
						}
						ctx, ok := cfg.Contexts[name]
						if !ok {
							return fmt.Errorf("%w %q", cliprofile.ErrNotFound, name)
						}
						fmt.Fprintf(c.Err, "Context %s (%s) will be removed from this computer.\n", name, ctx.Endpoint)
						if err := g.Prompter(c).Confirm("Remove it?"); err != nil {
							return err
						}
						delete(cfg.Contexts, name)
						if cfg.Current == name {
							cfg.Current = ""
						}
						if err := st.Save(cfg); err != nil {
							return err
						}
						for _, other := range cfg.Contexts {
							if other.Cluster == ctx.Cluster {
								return nil
							}
						}
						return st.RemoveTrust(ctx.Cluster)
					})
				},
			},
			contextTrustCommand(g),
		},
	}
}

func contextAddCommand(g *globals) *cli.Command {
	var key, walletKey string
	return &cli.Command{
		Name:  "add",
		Args:  "NAME [ENDPOINT]",
		Short: "Add a context and confirm the node's key",
		Long: `ENDPOINT is sfcp://HOST:PORT, unix:///PATH or /PATH; the default is
unix:///run/sfcdp.sock. The CLI asks the node who it is and shows its key
fingerprint; type yes only if it matches what the node's administrator
gives you ('sfcd identity' on the node). With --key the key is compared
instead, so no question is asked. -y does not skip this check.

--user and --tenant set the context's default user and tenant. The first
context becomes the current one.`,
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&key, "key", "", "expected node public `key` (64 hex characters), confirmed out of band")
			fs.StringVar(&walletKey, "wallet-key", "", "wallet `key` 'sfcli login' uses by default")
		},
		Run: func(c *cli.Context, args []string) error {
			if len(args) < 1 || len(args) > 2 {
				return cli.Usagef("add needs a context name and an optional endpoint")
			}
			name := args[0]
			if !cliprofile.ValidName(name) {
				return cli.Usagef("%q is not a valid context name", name)
			}
			raw := ""
			if len(args) == 2 {
				raw = args[1]
			}
			endpoint, err := cliprofile.ParseEndpoint(raw, true)
			if err != nil {
				return cli.Usagef("%q is not an endpoint: use sfcp://HOST:PORT, unix:///PATH or /PATH", raw)
			}
			ctx := cliprofile.Context{Endpoint: endpoint.URI, User: g.user, Tenant: g.tenant, Key: walletKey}
			if g.user != "" && !cliprofile.ValidUsername(g.user) || g.tenant != "" && !cliprofile.ValidKeyName(g.tenant) || walletKey != "" && !cliprofile.ValidKeyName(walletKey) {
				return cli.Usagef("invalid --user, --tenant or --wallet-key")
			}
			// Refuse a taken name before contacting anyone.
			if err := withStore(true, func(st *cliprofile.Store) error {
				cfg, err := st.Load()
				if _, taken := cfg.Contexts[name]; err == nil && taken {
					err = fmt.Errorf("%w: %s", cliprofile.ErrExists, name)
				}
				return err
			}); err != nil {
				return err
			}
			peer, how, err := confirmNode(g, c, endpoint, key, nil)
			if err != nil {
				return err
			}
			ctx.Cluster = hex.EncodeToString(peer.Cluster[:])
			return withStore(true, func(st *cliprofile.Store) error {
				unlock, err := st.Lock()
				if err != nil {
					return err
				}
				defer unlock()
				cfg, err := st.Load()
				if err != nil {
					return err
				}
				if _, ok := cfg.Contexts[name]; ok {
					return fmt.Errorf("%w: %s", cliprofile.ErrExists, name)
				}
				trust, err := st.Trust(ctx.Cluster)
				if err != nil {
					return err
				}
				if trust, err = cliprofile.TrustNode(trust, peer, how, time.Now()); err != nil {
					return err
				}
				if cfg.Contexts == nil {
					cfg.Contexts = map[string]cliprofile.Context{}
				}
				cfg.Contexts[name] = ctx
				if cfg.Current == "" {
					cfg.Current = name
				}
				if err := st.SaveTrust(trust); err != nil {
					return err
				}
				if err := st.Save(cfg); err != nil {
					return err
				}
				fmt.Fprintf(c.Err, "Added context %s (cluster %s, node %s).\n", name, ctx.Cluster[:12], peer.ID)
				if cfg.Current == name {
					fmt.Fprintf(c.Err, "Now using context %s.\n", name)
				}
				return nil
			})
		},
	}
}

func contextSetCommand(g *globals) *cli.Command {
	var walletKey, endpoint string
	return &cli.Command{
		Name:  "set",
		Args:  "NAME",
		Short: "Change a context's endpoint, default user, tenant or wallet key",
		Long: `Only the options given change: --endpoint, --user, --tenant and --wallet-key.
An empty value clears it, such as --tenant ''. --endpoint is for a node whose
address changed ('sfcli node set-endpoint'); trust it at the new address with
'sfcli context trust NAME' before the next command.`,
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&walletKey, "wallet-key", "", "default wallet `key` for 'sfcli login'")
			fs.StringVar(&endpoint, "endpoint", "", "new `endpoint` (sfcp://HOST:PORT, unix:///PATH or /PATH)")
		},
		Run: func(c *cli.Context, args []string) error {
			name, err := contextName(args)
			if err != nil {
				return err
			}
			if !c.Set("user") && !c.Set("tenant") && !c.Set("wallet-key") && !c.Set("endpoint") {
				return cli.Usagef("set needs --endpoint, --user, --tenant or --wallet-key")
			}
			if c.Set("endpoint") {
				e, err := cliprofile.ParseEndpoint(endpoint, true)
				if err != nil {
					return cli.Usagef("--endpoint %q: %v", endpoint, err)
				}
				endpoint = e.URI
			}
			return updateConfig(func(cfg *cliprofile.Config) error {
				ctx, ok := cfg.Contexts[name]
				if !ok {
					return fmt.Errorf("%w %q", cliprofile.ErrNotFound, name)
				}
				if c.Set("user") {
					ctx.User = g.user
				}
				if c.Set("tenant") {
					ctx.Tenant = g.tenant
				}
				if c.Set("wallet-key") {
					ctx.Key = walletKey
				}
				if c.Set("endpoint") {
					ctx.Endpoint = endpoint
				}
				if err := ctx.Validate(); err != nil {
					return cli.Usagef("invalid --endpoint, --user, --tenant or --wallet-key")
				}
				cfg.Contexts[name] = ctx
				return nil
			})
		},
	}
}

func contextTrustCommand(g *globals) *cli.Command {
	var key, forget string
	return &cli.Command{
		Name:  "trust",
		Args:  "NAME [ENDPOINT]",
		Short: "Trust another node of a context's cluster, or forget one",
		Long: `Asks the node at ENDPOINT (default: the context's endpoint) who it is and,
after you confirm its key, trusts it for the context's cluster. Use this
when a node is added, moves, or the context's own node was reinstalled
(forget the old key first with --forget NODE).`,
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&key, "key", "", "expected node public `key` (64 hex characters), confirmed out of band")
			fs.StringVar(&forget, "forget", "", "stop trusting this `node` instead")
		},
		Run: func(c *cli.Context, args []string) error {
			if len(args) < 1 || len(args) > 2 || forget != "" && len(args) != 1 {
				return cli.Usagef("trust needs a context name and an optional endpoint (none with --forget)")
			}
			var ctx cliprofile.Context
			if err := withStore(false, func(st *cliprofile.Store) error {
				cfg, err := st.Load()
				if err != nil {
					return err
				}
				var ok bool
				if ctx, ok = cfg.Contexts[args[0]]; !ok {
					return fmt.Errorf("%w %q", cliprofile.ErrNotFound, args[0])
				}
				return nil
			}); err != nil {
				return err
			}
			if forget != "" {
				return withStore(false, func(st *cliprofile.Store) error {
					unlock, err := st.Lock()
					if err != nil {
						return err
					}
					defer unlock()
					trust, err := st.Trust(ctx.Cluster)
					if err != nil {
						return err
					}
					i := slices.IndexFunc(trust.Nodes, func(n cliprofile.TrustedNode) bool { return n.ID == forget })
					if i < 0 {
						return fmt.Errorf("node %s is not trusted for this cluster", forget)
					}
					fmt.Fprintf(c.Err, "Node %s (%s) will no longer be trusted for cluster %s.\n", forget, fingerprint(trust.Nodes[i].Key), ctx.Cluster[:12])
					if err := g.Prompter(c).Confirm("Forget it?"); err != nil {
						return err
					}
					trust.Nodes = slices.Delete(trust.Nodes, i, i+1)
					return st.SaveTrust(trust)
				})
			}
			raw := ctx.Endpoint
			if len(args) == 2 {
				raw = args[1]
			}
			endpoint, err := cliprofile.ParseEndpoint(raw, true)
			if err != nil {
				return cli.Usagef("%q is not an endpoint: use sfcp://HOST:PORT, unix:///PATH or /PATH", raw)
			}
			cluster, _ := hex.DecodeString(ctx.Cluster)
			peer, how, err := confirmNode(g, c, endpoint, key, cluster)
			if err != nil {
				return err
			}
			return withStore(false, func(st *cliprofile.Store) error {
				unlock, err := st.Lock()
				if err != nil {
					return err
				}
				defer unlock()
				trust, err := st.Trust(ctx.Cluster)
				if err != nil {
					return err
				}
				if trust, err = cliprofile.TrustNode(trust, peer, how, time.Now()); err != nil {
					return err
				}
				if err := st.SaveTrust(trust); err != nil {
					return err
				}
				fmt.Fprintf(c.Err, "Trusted node %s at %s.\n", peer.ID, endpoint.URI)
				return nil
			})
		},
	}
}

// confirmNode asks the node at endpoint who it is and has the person
// confirm its key: with --key by comparison, else by its fingerprint on the
// terminal. -y never answers this question. A non-nil cluster must match.
func confirmNode(g *globals, c *cli.Context, endpoint cliprofile.Endpoint, key string, cluster []byte) (cliprofile.PeerIdentity, string, error) {
	var want [32]byte
	if key != "" {
		raw, err := hex.DecodeString(key)
		if err != nil || len(raw) != 32 || hex.EncodeToString(raw) != key {
			return cliprofile.PeerIdentity{}, "", cli.Usagef("--key must be 64 lower-case hex characters")
		}
		copy(want[:], raw)
	} else if g.noInput {
		return cliprofile.PeerIdentity{}, "", cli.Usagef("without a terminal (or with SFC_NONINTERACTIVE=1) add needs --key: the node's key cannot be confirmed")
	}
	ctx, cancel := g.Deadline(c)
	defer cancel()
	public, err := discoverNode(ctx, endpoint.Network, endpoint.Address)
	if err != nil {
		return cliprofile.PeerIdentity{}, "", fmt.Errorf("cannot reach %s: %w", endpoint.URI, err)
	}
	peer := cliprofile.PeerIdentity{Cluster: public.Cluster, Key: public.Key, ID: public.Node, Endpoint: endpoint}
	if !cliprofile.ValidKeyName(peer.ID) {
		return peer, "", fmt.Errorf("%s answered with node name %q, which this CLI cannot store", endpoint.URI, peer.ID)
	}
	if cluster != nil && string(cluster) != string(peer.Cluster[:]) {
		return peer, "", fmt.Errorf("%w: %s belongs to cluster %x, not this context's cluster", cliprofile.ErrTrust, endpoint.URI, peer.Cluster)
	}
	if key != "" {
		if want != peer.Key {
			return peer, "", fmt.Errorf("%w: %s answered with key %x, not the --key given", cliprofile.ErrTrust, endpoint.URI, peer.Key)
		}
		return peer, "out-of-band", nil
	}
	hexKey := hex.EncodeToString(peer.Key[:])
	fmt.Fprintf(c.Err, "Endpoint:  %s\nCluster:   %x\nNode:      %s\nNode key:  %s\n           %s\n", endpoint.URI, peer.Cluster, peer.ID, fingerprint(hexKey), hexKey)
	fmt.Fprintln(c.Err, "Check this key with the node's administrator ('sfcd identity' on the node).")
	p := g.Prompter(c)
	p.Yes = false
	if err := p.Confirm("Trust this node?"); err != nil {
		if errors.Is(err, cli.ErrNeedsConfirmation) {
			return peer, "", errors.New("the node's key needs confirmation on a terminal; or pass --key with the key above after checking it")
		}
		return peer, "", err
	}
	return peer, "fingerprint", nil
}

// fingerprint is the short form of a hex node key people compare.
func fingerprint(hexKey string) string {
	raw, err := hex.DecodeString(hexKey)
	if err != nil {
		return hexKey
	}
	digest := sha256.Sum256(raw)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:])
}

func contextName(args []string) (string, error) {
	if len(args) != 1 {
		return "", cli.Usagef("needs one context name")
	}
	if !cliprofile.ValidName(args[0]) {
		return "", cli.Usagef("%q is not a valid context name", args[0])
	}
	return args[0], nil
}

// withStore opens ~/.sfc for one command.
func withStore(create bool, run func(*cliprofile.Store) error) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	st, err := cliprofile.OpenStore(home, create)
	if errors.Is(err, os.ErrNotExist) {
		return cliprofile.ErrNoContext
	}
	if err != nil {
		return err
	}
	defer st.Close()
	return run(st)
}

// updateConfig changes config.yaml under the store lock.
func updateConfig(change func(*cliprofile.Config) error) error {
	return withStore(false, func(st *cliprofile.Store) error {
		unlock, err := st.Lock()
		if err != nil {
			return err
		}
		defer unlock()
		cfg, err := st.Load()
		if err != nil {
			return err
		}
		if err := change(&cfg); err != nil {
			return err
		}
		return st.Save(cfg)
	})
}
