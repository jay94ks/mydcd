// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/jay94ks/seafield/internal/buildinfo"
	"os"
	"sort"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/cliprofile"
)

// The account commands keep the login, logout and enrollment flows of the
// old command path and give them the new command line and output. The old
// path goes in the final cleanup, when these flows move here.

// legacy runs an old-path command line with the selected context, user and
// tenant, and returns what it printed on standard output (JSON).
func (g *globals) legacy(c *cli.Context, args ...string) ([]byte, error) {
	if g.timeout <= 0 || g.timeout > 5*time.Minute {
		return nil, cli.Usagef("--timeout must be more than 0 and at most 5m")
	}
	prefix := []string{"--timeout", g.timeout.String()}
	if g.context != "" {
		prefix = append(prefix, "--cluster", g.context)
	}
	if g.tenant != "" {
		prefix = append(prefix, "--tenant", g.tenant)
	}
	if g.user != "" {
		prefix = append(prefix, "--user", g.user)
	}
	if g.noInput {
		prefix = append(prefix, "--no-input")
	}
	var out bytes.Buffer
	if code := runLegacy(append(prefix, args...), &out, c.Err); code != 0 {
		// The old path already printed why.
		return out.Bytes(), cli.ExitError{Code: code}
	}
	return out.Bytes(), nil
}

// contextDefaults returns the selected context's default user and wallet key.
func (g *globals) contextDefaults() (user, key string) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", ""
	}
	selected, err := resolveCommandProfile(home, g.context, "", "")
	if err != nil {
		return "", ""
	}
	return selected.Target.Username, selected.Target.WalletKey
}

func loginCommand(g *globals) *cli.Command {
	var password, token, stdin bool
	var key, credential, approveWith string
	return &cli.Command{
		Name:  "login",
		Args:  "[USER]",
		Short: "Log in and save the session in the wallet",
		Long: `Logs in with a wallet key (the default), a password or a token. USER
defaults to --user, then the context's user. The key defaults to the
context's wallet key. A password or token is asked on the terminal, or read
from standard input with --stdin; it is never saved.

--approve-with KEY also signs the new password or token session with that
registered wallet key, which clusters that require independent approval ask
for.`,
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&password, "password", false, "log in with a password")
			fs.BoolVar(&token, "token", false, "log in with a token")
			fs.BoolVar(&stdin, "stdin", false, "read the password or token from standard input")
			fs.StringVar(&key, "key", "", "wallet `key` to log in with")
			fs.StringVar(&credential, "credential", "", "credential `ID` when the user has more than one of that kind")
			fs.StringVar(&approveWith, "approve-with", "", "wallet `key` that approves a password or token session")
		},
		Run: func(c *cli.Context, args []string) error {
			if len(args) > 1 || password && token {
				return cli.Usagef("login takes at most one user and one of --password or --token")
			}
			user := g.user
			if len(args) == 1 {
				if user != "" && user != args[0] {
					return cli.Usagef("USER and --user differ")
				}
				user = args[0]
			}
			defaultUser, defaultKey := g.contextDefaults()
			if user == "" {
				user = defaultUser
			}
			if user == "" {
				return cli.Usagef("login needs a user: give USER or set one with 'sfcli context set NAME --user USER'")
			}
			if !cliprofile.ValidUsername(user) {
				return cli.Usagef("%q is not a valid user name", user)
			}
			method := "private-key"
			if password {
				method = "password"
			} else if token {
				method = "token"
			}
			old := []string{"login", "--user", user, "--method", method}
			if method == "private-key" {
				if stdin || credential != "" || approveWith != "" {
					return cli.Usagef("--stdin, --credential and --approve-with go with --password or --token")
				}
				if key == "" {
					key = defaultKey
				}
				if key == "" {
					return cli.Usagef("login needs --key NAME, --password or --token")
				}
				old = append(old, "--key", key)
			} else {
				if key != "" {
					return cli.Usagef("--key goes with a key login; use --approve-with to approve a %s session", method)
				}
				if credential != "" {
					old = append(old, "--credential", credential)
				}
				if approveWith != "" {
					old = append(old, "--approval-key", approveWith)
				}
				if stdin || !term.IsTerminal(int(os.Stdin.Fd())) {
					old = append(old, "--"+method+"-stdin")
				}
			}
			// The old path takes the user from login --user, not the global.
			saved := g.user
			g.user = ""
			raw, err := g.legacy(c, old...)
			g.user = saved
			if err != nil {
				return err
			}
			return printAccount(g, c, raw, "Logged in as")
		},
	}
}

func logoutCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "logout",
		Short: "End the session and forget it",
		Long: `Asks the server to end the current session. If an earlier logout's reply
was lost, running logout again finishes that same request; it is never sent
as a new one.`,
		Run: func(c *cli.Context, args []string) error {
			if len(args) != 0 {
				return cli.Usagef("logout takes no arguments")
			}
			raw, err := g.legacy(c, "logout")
			var exit cli.ExitError
			if errors.As(err, &exit) && exit.Code == 4 {
				// The original request is saved: finish it with the same ID.
				fmt.Fprintln(c.Err, "Sending the saved logout request again.")
				raw, err = g.legacy(c, "logout", "--resume-original")
			}
			if err != nil {
				return err
			}
			var v map[string]any
			if json.Unmarshal(raw, &v) != nil {
				return errors.New("unexpected logout reply")
			}
			return cli.Print(c.Out, g.output.Format(), v, func() cli.Rows {
				return fieldRows(v, "status", "request")
			})
		},
	}
}

func whoamiCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "whoami",
		Short: "Show who you are logged in as and your tenants",
		Run: func(c *cli.Context, args []string) error {
			if len(args) != 0 {
				return cli.Usagef("whoami takes no arguments")
			}
			raw, err := g.legacy(c, "whoami")
			if err != nil {
				return err
			}
			return printAccount(g, c, raw, "")
		},
	}
}

func enrollCommand(g *globals) *cli.Command {
	var key, userID string
	return &cli.Command{
		Name:  "enroll",
		Args:  "USER",
		Short: "Register the first system administrator of a new cluster",
		Long: `Only a newly initialized cluster accepts this, once, signed with the
bootstrap admin key given to 'sfcd init'. Running it again with the same
user finishes the same request.`,
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&key, "key", "", "wallet `key` registered as the bootstrap admin key")
			fs.StringVar(&userID, "user-id", "", "stable user `ID` (default: USER)")
		},
		Run: func(c *cli.Context, args []string) error {
			if len(args) != 1 || key == "" {
				return cli.Usagef("enroll needs USER and --key NAME")
			}
			if userID == "" {
				userID = args[0]
			}
			if !cliprofile.ValidUsername(args[0]) || !cliprofile.ValidKeyName(userID) || !cliprofile.ValidKeyName(key) {
				return cli.Usagef("invalid USER, --user-id or --key")
			}
			saved := g.user
			g.user = ""
			raw, err := g.legacy(c, "enroll-admin", "--user-id", userID, "--user", args[0], "--key", key, "--request-id", "enroll-"+userID)
			g.user = saved
			if err != nil {
				return err
			}
			var v map[string]any
			if json.Unmarshal(raw, &v) != nil {
				return errors.New("unexpected enroll reply")
			}
			fmt.Fprintf(c.Err, "Enrolled %s as system administrator. Log in with 'sfcli login %s --key %s'.\n", args[0], args[0], key)
			return cli.Print(c.Out, g.output.Format(), v, func() cli.Rows { return fieldRows(v) })
		},
	}
}

func versionCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "version",
		Short: "Show the CLI version and, if a context is set, the server's",
		Run: func(c *cli.Context, args []string) error {
			if len(args) != 0 {
				return cli.Usagef("version takes no arguments")
			}
			v := map[string]any{"client": buildinfo.Version()}
			if _, err := resolveCommandProfile(mustHome(), g.context, "", ""); err == nil {
				var discard bytes.Buffer
				saved := c.Err
				c.Err = &discard
				raw, err := g.legacy(c, "server-version")
				c.Err = saved
				var server map[string]any
				if err == nil && json.Unmarshal(raw, &server) == nil {
					v["server"] = server
				} else {
					v["server_error"] = strings.TrimSpace(discard.String())
				}
			}
			return cli.Print(c.Out, g.output.Format(), v, func() cli.Rows {
				t := cli.Rows{Header: []string{"", "version"}}
				t.Add("client", buildinfo.Version())
				if s, ok := v["server"].(map[string]any); ok {
					t.Add("server", fmt.Sprintf("%v (protocol %v)", s["Version"], s["Protocol"]))
				} else if e, ok := v["server_error"].(string); ok {
					t.Add("server", "unreachable: "+e)
				}
				return t
			})
		},
	}
}

func mustHome() string {
	home, _ := os.UserHomeDir()
	return home
}

// printAccount shows a login or whoami reply.
func printAccount(g *globals, c *cli.Context, raw []byte, say string) error {
	var v map[string]any
	if err := json.Unmarshal(raw, &v); err != nil {
		return errors.New("unexpected reply from the server")
	}
	delete(v, "schema")
	if say != "" {
		fmt.Fprintf(c.Err, "%s %v.\n", say, v["username"])
	}
	return cli.Print(c.Out, g.output.Format(), v, func() cli.Rows {
		t := cli.Rows{Header: []string{"field", "value"}}
		t.Add("user", v["username"])
		if u, ok := v["user"].(map[string]any); ok {
			t.Add("user id", u["ID"])
			if admin, _ := u["SystemAdmin"].(bool); admin {
				t.Add("system admin", "yes")
			}
		}
		if v["tenant"] != nil {
			t.Add("tenant", v["tenant"])
		}
		if tenants, ok := v["tenants"].([]any); ok {
			names := []string{}
			for _, x := range tenants {
				if m, ok := x.(map[string]any); ok {
					names = append(names, fmt.Sprint(m["Tenant"], " (", m["Role"], ")"))
				} else {
					names = append(names, fmt.Sprint(x))
				}
			}
			t.Add("tenants", strings.Join(names, ", "))
		}
		if exp, ok := v["expires_at"].(float64); ok {
			t.Add("expires", time.Unix(int64(exp), 0).Local().Format("2006-01-02 15:04"))
		}
		return t
	})
}

func fieldRows(v map[string]any, keys ...string) cli.Rows {
	t := cli.Rows{Header: []string{"field", "value"}}
	if len(keys) == 0 {
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
	}
	for _, k := range keys {
		if k != "schema" {
			if x, ok := v[k]; ok {
				t.Add(k, fmt.Sprint(x))
			}
		}
	}
	return t
}
