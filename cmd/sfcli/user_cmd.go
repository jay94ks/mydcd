// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/cliprofile"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/credentials"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
)

// user: 사용자 계정과 로그인 수단 (devel/design/cli-and-formats.md).

func userCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "user",
		Short: "Manage user accounts and their keys, passwords and sessions",
		Sub: []*cli.Command{
			userListCommand(g),
			userShowCommand(g),
			userCreateCommand(g),
			userKeyCommand(g),
			userIssueCommand(g, access.Password),
			userIssueCommand(g, access.Token),
			userRevokeSessionCommand(g),
			userScopeCommand(g),
		},
	}
}

func userArg(args []string, usage string) (string, error) {
	if len(args) != 1 {
		return "", cli.Usagef("expected %s", usage)
	}
	if !cliprofile.ValidUsername(args[0]) {
		return "", cli.Usagef("%q is not a valid user name", args[0])
	}
	return args[0], nil
}

func userListCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "list",
		Short: "List user accounts (system administrator)",
		Run: guard(func(c *cli.Context, args []string) error {
			if len(args) != 0 {
				return cli.Usagef("list takes no arguments")
			}
			s, err := openSession(g, c)
			if err != nil {
				return err
			}
			defer s.Close()
			users := []access.PublicUser{}
			after, revision := "", uint64(0)
			for {
				ctx, cancel := g.Deadline(c)
				reply, err := s.Client.UsersPage(ctx, s.Target, s.Stored.Session, after)
				cancel()
				if err != nil {
					return err
				}
				if after != "" && reply.UsersRevision != revision {
					return errors.New("users changed while reading them; try again")
				}
				revision = reply.UsersRevision
				users = append(users, reply.Users...)
				if after = reply.UsersNext; after == "" {
					break
				}
			}
			return cli.Print(c.Out, g.output.Format(), users, func() cli.Rows {
				r := cli.Rows{Header: []string{"user", "enabled", "admin", "credentials"}}
				for _, u := range users {
					var creds []string
					for _, k := range u.Credentials {
						if k.Enabled {
							creds = append(creds, k.ID+"("+string(k.Method)+")")
						}
					}
					r.Add(u.Username, u.Enabled, u.SystemAdmin, strings.Join(creds, ","))
				}
				return r
			})
		}),
	}
}

func readUser(c *cli.Context, g *globals, s *session, username string) (access.User, error) {
	ctx, cancel := g.Deadline(c)
	defer cancel()
	reply, err := s.Client.UserCredentials(ctx, s.Target, s.Stored.Session, username)
	if err != nil {
		return access.User{}, err
	}
	if reply.CredentialUser == nil {
		return access.User{}, fmt.Errorf("no user %s", username)
	}
	return *reply.CredentialUser, nil
}

func userShowCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "show",
		Args:  "USER",
		Short: "Show an account and its credentials (system administrator)",
		Run: guard(func(c *cli.Context, args []string) error {
			username, err := userArg(args, "USER")
			if err != nil {
				return err
			}
			s, err := openSession(g, c)
			if err != nil {
				return err
			}
			defer s.Close()
			u, err := readUser(c, g, s, username)
			if err != nil {
				return err
			}
			return cli.Print(c.Out, g.output.Format(), access.PublicUserOf(u), nil)
		}),
	}
}

// newUserID is the account's stable ID: the user name when it is a valid
// ID, otherwise a random one.
func newUserID(username string) string {
	if lifecycle.ValidID(username) && cli.ValidID(username) {
		return username
	}
	return "u" + cli.NewID()[1:]
}

func parsePublicKey(text string) ([32]byte, error) {
	key, err := identity.ParseKey(text)
	if err != nil || text != hex.EncodeToString(key[:]) {
		return [32]byte{}, cli.Usagef("--public-key must be an Ed25519 public key in hex (sfcli key show NAME prints it)")
	}
	return key, nil
}

func userCreateCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var publicKey, keyName string
	var admin, automation bool
	return &cli.Command{
		Name:  "create",
		Args:  "USER",
		Short: "Create a user account (system administrator)",
		Long: `Create a user account. Without --public-key the account has no way to
log in yet; add one with 'user key add', 'user issue-password' or
'user issue-token'. A system administrator needs a key from the start.`,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.StringVar(&publicKey, "public-key", "", "the user's Ed25519 public `key` in hex")
			fs.StringVar(&keyName, "key-name", "key", "`name` of that key on the account")
			fs.BoolVar(&admin, "admin", false, "make the user a system administrator")
			fs.BoolVar(&automation, "automation", false, "an account for scripts: keys only, no passwords or tokens")
		},
		Run: guard(func(c *cli.Context, args []string) error {
			username, err := userArg(args, "USER")
			if err != nil {
				return err
			}
			u := access.User{ID: newUserID(username), Username: username, Enabled: true, SystemAdmin: admin, AutomationOnly: automation, Credentials: []access.Credential{}}
			if publicKey != "" {
				key, err := parsePublicKey(publicKey)
				if err != nil {
					return err
				}
				if !lifecycle.ValidID(keyName) {
					return cli.Usagef("--key-name %q is not a valid name", keyName)
				}
				u.Credentials = append(u.Credentials, access.Credential{ID: keyName, Method: access.PrivateKey, PublicKey: key, Enabled: true})
			} else if admin {
				return cli.Usagef("a system administrator needs --public-key")
			}
			s, err := openSession(g, c)
			if err != nil {
				return err
			}
			defer s.Close()
			summary := "user create " + username
			if admin {
				summary += " --admin"
			}
			if _, err = g.send(c, s, change{Summary: summary, ID: id.Get(), Action: "put-user", Expected: 0, Payload: u}); err != nil {
				return err
			}
			fmt.Fprintf(c.Out, "user %s created\n", username)
			return nil
		}),
	}
}

func userKeyCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "key",
		Short: "Add or disable a user's login keys (system administrator)",
		Sub:   []*cli.Command{userKeyAddCommand(g), userKeyDisableCommand(g)},
	}
}

func userKeyAddCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var revision cli.RevisionFlag
	var publicKey, operations string
	return &cli.Command{
		Name:  "add",
		Args:  "USER KEY --public-key HEX",
		Short: "Add a login key to an account",
		Long: `Add a login key named KEY to an account. Every session of the account
ends: the user logs in again. --operations limits what the key may do to
the listed server actions; the user's roles still apply.`,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.Var(&revision, "if-revision", "change only if the account is still at this `revision`")
			fs.StringVar(&publicKey, "public-key", "", "Ed25519 public `key` in hex")
			fs.StringVar(&operations, "operations", "", "only these server `actions`, separated by commas")
		},
		Run: guard(func(c *cli.Context, args []string) error {
			if len(args) != 2 || !cliprofile.ValidUsername(args[0]) || !lifecycle.ValidID(args[1]) {
				return cli.Usagef("expected USER KEY --public-key HEX")
			}
			key, err := parsePublicKey(publicKey)
			if err != nil {
				return err
			}
			var ops []string
			if operations != "" {
				ops = strings.Split(operations, ",")
				if !access.ValidCredentialOperations(ops) {
					return cli.Usagef("--operations has an unknown or repeated action")
				}
			}
			// A system administrator adds the key without a proof, to any
			// account its own included.
			return changeUser(c, g, &id, &revision, args[0], "user key add "+args[0]+" "+args[1], func(_ *session, u access.User) (string, any, error) {
				return "add-credential", access.CredentialAddition{User: u.ID, Credential: access.CredentialKey{ID: args[1], Method: access.PrivateKey, PublicKey: key}, Operations: ops}, nil
			})
		}),
	}
}

func userKeyDisableCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var revision cli.RevisionFlag
	return &cli.Command{
		Name:  "disable",
		Args:  "USER KEY",
		Short: "Disable a login key; every session of the account ends",
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.Var(&revision, "if-revision", "change only if the account is still at this `revision`")
		},
		Run: guard(func(c *cli.Context, args []string) error {
			if len(args) != 2 || !cliprofile.ValidUsername(args[0]) || !lifecycle.ValidID(args[1]) {
				return cli.Usagef("expected USER KEY")
			}
			return changeUser(c, g, &id, &revision, args[0], "user key disable "+args[0]+" "+args[1], func(_ *session, u access.User) (string, any, error) {
				return "disable-credential", access.CredentialDisable{User: u.ID, Credential: args[1]}, nil
			})
		}),
	}
}

// changeUser sends the account change edit makes from the current account
// (its action and payload), at the account's revision, after confirmation.
func changeUser(c *cli.Context, g *globals, id *cli.IDFlag, revision *cli.RevisionFlag, username, summary string, edit func(*session, access.User) (string, any, error)) error {
	s, err := openSession(g, c)
	if err != nil {
		return err
	}
	defer s.Close()
	u, err := readUser(c, g, s, username)
	if err != nil {
		return err
	}
	rev, err := revision.Resolve(func() (uint64, error) { return u.Revision, nil })
	if err != nil {
		return err
	}
	action, payload, err := edit(s, u)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.Err, "Every session of %s will end; they log in again.\n", username)
	if err = g.Prompter(c).Confirm("Change " + username + "?"); err != nil {
		return err
	}
	if _, err = g.send(c, s, change{Summary: summary, ID: id.Get(), Action: action, Expected: rev, Payload: payload}); err != nil {
		return err
	}
	fmt.Fprintf(c.Out, "%s changed\n", username)
	return nil
}

// userScopeCommand: set-account-scope, the account's action ceiling and
// key-only login on top of each credential's own ceiling.
func userScopeCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var revision cli.RevisionFlag
	var add, remove, keyOnly string
	var unlimited bool
	return &cli.Command{
		Name:  "scope",
		Args:  "USER",
		Short: "Change the actions an account may sign and its key-only login (system administrator)",
		Long: `--add and --remove change the account's action limit, one action or more
(comma separated); adding to an account with no limit starts one.
--unlimited lifts the limit. --key-only on|off allows private-key logins
only, or again passwords and tokens. Adding an action the limit has, or
removing one it lacks, is refused (someone changed it since). Every session
of the account ends.`,
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&add, "add", "", "comma-separated action `names` to allow, such as restart-task,pause-app-cd")
			fs.StringVar(&remove, "remove", "", "comma-separated action `names` to take out of the limit")
			fs.BoolVar(&unlimited, "unlimited", false, "lift the action limit")
			fs.StringVar(&keyOnly, "key-only", "", "`on` or off: private-key logins only")
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.Var(&revision, "if-revision", "change only if the account is still at this `revision`")
		},
		Run: guard(func(c *cli.Context, args []string) error {
			username, err := userArg(args, "USER")
			if err != nil {
				return err
			}
			var q access.AccountScope
			for _, part := range []struct {
				text string
				list *[]string
				flag string
			}{{add, &q.Add, "--add"}, {remove, &q.Remove, "--remove"}} {
				if part.text == "" {
					continue
				}
				*part.list = strings.Split(part.text, ",")
				if !access.ValidCredentialOperations(*part.list) {
					return cli.Usagef("%s: 1 to 64 distinct action names", part.flag)
				}
			}
			switch keyOnly {
			case "":
			case "on", "off":
				v := keyOnly == "on"
				q.KeyOnly = &v
			default:
				return cli.Usagef("--key-only is on or off")
			}
			q.Unlimited = unlimited
			if len(q.Add)+len(q.Remove) == 0 && !unlimited && q.KeyOnly == nil || unlimited && len(q.Add)+len(q.Remove) > 0 {
				return cli.Usagef("give --add and/or --remove, or --unlimited; --key-only on|off goes with either or alone")
			}
			s, err := openSession(g, c)
			if err != nil {
				return err
			}
			defer s.Close()
			u, err := readUser(c, g, s, username)
			if err != nil {
				return err
			}
			q.User = u.ID
			rev, err := revision.Resolve(func() (uint64, error) { return u.Revision, nil })
			if err != nil {
				return err
			}
			fmt.Fprintf(c.Err, "Every session of %s will end; they log in again.\n", username)
			if err = g.Prompter(c).Confirm("Change the scope of " + username + "?"); err != nil {
				return err
			}
			if _, err = g.send(c, s, change{Summary: "user scope " + username, ID: id.Get(), Action: "set-account-scope", Expected: rev, Payload: q}); err != nil {
				return err
			}
			fmt.Fprintf(c.Out, "%s changed\n", username)
			return nil
		}),
	}
}

func userRevokeSessionCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var revision cli.RevisionFlag
	return &cli.Command{
		Name:  "revoke-session",
		Args:  "USER SESSION",
		Short: "End one session of an account",
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.Var(&revision, "if-revision", "change only if the account is still at this `revision`")
		},
		Run: guard(func(c *cli.Context, args []string) error {
			if len(args) != 2 || !cliprofile.ValidUsername(args[0]) || args[1] == "" || len(args[1]) > 128 {
				return cli.Usagef("expected USER SESSION")
			}
			s, err := openSession(g, c)
			if err != nil {
				return err
			}
			defer s.Close()
			u, err := readUser(c, g, s, args[0])
			if err != nil {
				return err
			}
			if u.ID == s.Stored.Session.User && args[1] == s.Stored.Session.ID {
				return cli.Usagef("that is this session; use 'sfcli logout'")
			}
			rev, err := revision.Resolve(func() (uint64, error) { return u.Revision, nil })
			if err != nil {
				return err
			}
			if _, err = g.send(c, s, change{Summary: "user revoke-session " + args[0] + " " + args[1], ID: id.Get(), Action: "revoke-session", Expected: rev, Payload: control.SessionRevocation{User: u.ID, Session: args[1]}}); err != nil {
				return err
			}
			fmt.Fprintf(c.Out, "session %s of %s ended\n", args[1], args[0])
			return nil
		}),
	}
}

// user issue-password / issue-token give an account its first password or a
// single-use token through a credential provider installed on a server.
// The provider step and the activation are two server calls; the provider's
// answer is saved under the operation ID so 'sfcli op resume' finishes it
// without the secret.
func userIssueCommand(g *globals, method access.Method) *cli.Command {
	var id cli.IDFlag
	var revision cli.RevisionFlag
	var name, profile, node, out, expires string
	cmd := &cli.Command{
		Name:  "issue-password",
		Args:  "USER [--profile PROFILE]",
		Short: "Set a user's password (read from the terminal or standard input)",
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.Var(&revision, "if-revision", "change only if the account is still at this `revision`")
			fs.StringVar(&name, "name", string(method), "`name` of the credential on the account")
			fs.StringVar(&profile, "profile", "", "credential provider `profile`: builtin (the cluster's own store) or the external Vault installed on the server (default: that Vault if installed, else builtin)")
			fs.StringVar(&node, "node", "", "`server` that stores it; for builtin a voter (default: the one you are connected to)")
			if method == access.Token {
				fs.StringVar(&out, "out", "", "write the token to this new `file` (mode 0600)")
				fs.StringVar(&expires, "expires", "24h", "how long the token logs in: `1h`, 24h or 7d")
			}
		},
	}
	if method == access.Token {
		cmd.Name, cmd.Args, cmd.Short = "issue-token", "USER [--profile PROFILE] --out FILE", "Issue a single-use login token into a file"
	}
	cmd.Run = guard(func(c *cli.Context, args []string) error {
		username, err := userArg(args, cmd.Args)
		if err != nil {
			return err
		}
		if !lifecycle.ValidID(name) || profile != "" && !lifecycle.ValidID(profile) || node != "" && !lifecycle.ValidID(node) {
			return cli.Usagef("--name, --profile and --node must be valid names")
		}
		var tokenFile *os.File
		var seconds int64
		if method == access.Token {
			if seconds = map[string]int64{"1h": 3600, "24h": 86400, "7d": 7 * 86400}[expires]; seconds == 0 {
				return cli.Usagef("--expires is 1h, 24h or 7d")
			}
			if out == "" {
				return cli.Usagef("give --out FILE for the token")
			}
			if tokenFile, err = os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600); err != nil {
				return err
			}
			defer tokenFile.Close()
		}
		var password []byte
		defer func() { clear(password) }()
		if method == access.Password {
			if password, err = readNewPassword(c, g); err != nil {
				return err
			}
		}
		s, err := openSession(g, c)
		if err != nil {
			return err
		}
		defer s.Close()
		owner := s.Target
		if node != "" {
			found := false
			for _, p := range s.Client.Peers {
				if p.ID == node {
					owner, found = p, true
				}
			}
			if !found {
				return fmt.Errorf("server %s is not in this context", node)
			}
		}
		if profile == "" {
			ctx, cancel := g.Deadline(c)
			profile, err = s.Client.InitialCredentialProfile(ctx, owner, s.Stored.Session)
			cancel()
			if err != nil {
				return fmt.Errorf("could not ask %s for its credential provider: %w", owner.ID, err)
			}
			if !lifecycle.ValidID(profile) {
				return errors.New("the server named an invalid credential provider")
			}
		}
		u, err := readUser(c, g, s, username)
		if err != nil {
			return err
		}
		rev, err := revision.Resolve(func() (uint64, error) { return u.Revision, nil })
		if err != nil {
			return err
		}
		opID := id.Get()
		summary := fmt.Sprintf("user %s %s --profile %s --name %s", cmd.Name, username, profile, name)
		if err = g.Record(s, "user-issue", summary, opID); err != nil {
			return err
		}
		r := credentials.InitialRequest{Schema: 1, Cluster: s.Client.Cluster, Owner: [32]byte(owner.Key), User: u.ID, Username: u.Username, Credential: name, Profile: profile, Method: method, ExpectedUserRevision: rev, At: time.Now().Unix(), Seconds: seconds}
		if _, err = rand.Read(r.Operation[:]); err != nil {
			return err
		}
		if _, err = userauth.StageInitialIntent(s.Home, s.Client, s.Stored.Session, opID, r); err != nil {
			return err
		}
		token, err := issueInitial(c, g, s, opID, summary, password)
		defer clear(token)
		if err != nil {
			return err
		}
		if method == access.Token {
			if len(token) == 0 {
				return errors.New("the provider returned no token")
			}
			_, err = tokenFile.Write(token)
			if closeErr := tokenFile.Close(); err == nil {
				err = closeErr
			}
			if err != nil {
				return fmt.Errorf("the token was activated but could not be written (%v); it cannot be shown again, issue a new one", err)
			}
			fmt.Fprintf(c.Out, "token for %s written to %s\n", username, out)
			return nil
		}
		fmt.Fprintf(c.Out, "password of %s set\n", username)
		return nil
	})
	return cmd
}

// readNewPassword reads a password from the terminal (asked twice) or from
// standard input when it is not a terminal.
func readNewPassword(c *cli.Context, g *globals) ([]byte, error) {
	if f, ok := c.In.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		if g.noInput {
			return nil, errors.New("the password is read from the terminal; --no-input forbids that (pipe it on standard input)")
		}
		fmt.Fprint(c.Err, "New password: ")
		first, err := identity.ReadPassword(int(f.Fd()))
		fmt.Fprintln(c.Err)
		if err != nil {
			return nil, err
		}
		fmt.Fprint(c.Err, "Repeat: ")
		second, err := identity.ReadPassword(int(f.Fd()))
		fmt.Fprintln(c.Err)
		defer clear(second)
		if err != nil || string(first) != string(second) {
			clear(first)
			return nil, errors.New("the passwords differ")
		}
		if len(first) == 0 || len(first) > 1024 {
			clear(first)
			return nil, errors.New("the password must be 1-1024 bytes")
		}
		return first, nil
	}
	in := c.In
	f, _ := in.(*os.File)
	if f == nil {
		return nil, errors.New("no password input")
	}
	return readLoginSecret(f, true, c.Err, access.Password)
}

// issueInitial runs the provider step (unless its answer is saved) and then
// the activation. password is nil on resume: an intent already sent to the
// provider is only observed again.
func issueInitial(c *cli.Context, g *globals, s *session, opID, summary string, password []byte) ([]byte, error) {
	intent, err := userauth.LoadInitialIntent(s.Home, s.Client, s.Stored.Session, opID)
	if err != nil {
		return nil, err
	}
	owner, ok := peerByKey(s.Client.Peers, intent.Request.Owner)
	if !ok {
		return nil, errors.New("the server holding the credential provider is no longer in this context")
	}
	var token []byte
	fact := intent.Fact
	if fact == nil {
		ctx, cancel := g.Deadline(c)
		defer cancel()
		var reply userauth.Reply
		switch {
		case intent.Dispatched:
			reply, err = s.Client.ObserveInitialCredential(ctx, owner, s.Stored.Session, intent.Request)
		case password == nil && intent.Request.Method == access.Password:
			return nil, errors.New("the password was never sent; run the command again")
		default:
			if err = userauth.MarkInitialDispatch(s.Home, s.Client, s.Stored.Session, opID); err != nil {
				return nil, err
			}
			reply, err = s.Client.StageInitialCredential(ctx, owner, s.Stored.Session, intent.Request, password)
		}
		token = reply.InitialCredentialToken
		if err != nil {
			clear(token)
			return nil, errOutcomeUnknown{id: opID, err: err}
		}
		if reply.InitialCredentialFact == nil {
			clear(token)
			return nil, errOutcomeUnknown{id: opID, err: errors.New("the provider did not confirm")}
		}
		fact = reply.InitialCredentialFact
		if err = userauth.RecordInitialFact(s.Home, s.Client, s.Stored.Session, opID, *fact); err != nil {
			clear(token)
			return nil, err
		}
	}
	_, err = g.send(c, s, change{Kind: "user-issue", Summary: summary, ID: opID, Action: "issue-initial-credential", Expected: intent.Request.ExpectedUserRevision, Payload: *fact})
	if err != nil {
		clear(token)
		return nil, err
	}
	return token, nil
}

func peerByKey(peers []sfcp.Peer, key [32]byte) (sfcp.Peer, bool) {
	for _, p := range peers {
		if [32]byte(p.Key) == key {
			return p, true
		}
	}
	return sfcp.Peer{}, false
}

func init() {
	opKinds["user-issue"] = func(g *globals) cli.Handler {
		activation := changeHandler(g, nil, false)
		settle := func(c *cli.Context, op cli.Op, resume bool) (cli.State, string, error) {
			s, err := openOpSession(g, c, op)
			if err != nil {
				return "", "", err
			}
			if _, err = userauth.LoadOperation(s.Home, s.Client, s.Stored.Session, op.ID); err == nil {
				s.Close()
				if resume {
					return activation.Resume(c, op)
				}
				return activation.Show(c, op)
			}
			defer s.Close()
			if !resume {
				return cli.Sending, "the credential provider step has not finished; 'sfcli op resume' completes it", nil
			}
			token, err := issueInitial(c, g, s, op.ID, op.Summary, nil)
			clear(token)
			if err != nil {
				return "", "", err
			}
			detail := "applied"
			if len(token) != 0 {
				detail = "applied; the token could not be delivered on resume, issue a new one"
			}
			return cli.Done, detail, nil
		}
		return cli.Handler{
			Show:   func(c *cli.Context, op cli.Op) (cli.State, string, error) { return settle(c, op, false) },
			Resume: func(c *cli.Context, op cli.Op) (cli.State, string, error) { return settle(c, op, true) },
		}
	}
}
