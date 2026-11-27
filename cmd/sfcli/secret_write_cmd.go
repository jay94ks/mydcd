// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/secrets"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
	"golang.org/x/term"
)

// A write stores secret values or a group password in the external Vault.
// It takes several steps: the server prepares and dispatches it, the CLI
// sends the values straight to the writer node, then the server records and
// publishes what the node stored. Every step hangs off the write ID, which
// is also the operation ID, so `sfcli op resume ID` continues the same write.
// A value is sent to the writer node at most once: after that the CLI only
// asks the node what became of it.

const maxSecretBytes = 16 << 10

func init() {
	opKinds["secret-write"] = func(g *globals) cli.Handler {
		run := func(c *cli.Context, op cli.Op, resume bool) (cli.State, string, error) {
			s, err := g.opSession(c, op)
			if err != nil {
				return "", "", err
			}
			defer s.Close()
			intent, err := userauth.LoadSecretWrite(s.Home, s.Client, s.Stored.Session, op.Tenant, op.ID)
			if errors.Is(err, userauth.ErrOperationMissing) && op.Tenant != "" {
				intent, err = userauth.LoadSecretWrite(s.Home, s.Client, s.Stored.Session, "", op.ID)
			}
			if errors.Is(err, userauth.ErrOperationMissing) {
				return cli.Failed, "not sent", nil
			}
			if err != nil {
				return "", "", err
			}
			if !resume {
				ctx, cancel := g.Deadline(c)
				defer cancel()
				plan, err := s.Client.PlanVaultWrite(ctx, s.Target, s.Stored.Session, control.VaultWritePlanRequest{Realm: intent.Realm, ID: intent.Request.ID})
				if err != nil {
					return "", "", err
				}
				st, detail := writeState(plan)
				return st, detail, nil
			}
			values := func(q secrets.WriteRequest) (map[string][]byte, error) {
				if q.Kind == secrets.VerifierWrite {
					return g.groupVerifier(c, "", q.Object)
				}
				return g.secretValues(c, nil, q)
			}
			plan, err := g.runSecretWrite(c, s, intent, true, values)
			if err != nil {
				return cli.Sending, err.Error(), nil
			}
			st, detail := writeState(plan)
			return st, detail, nil
		}
		return cli.Handler{
			Show:   func(c *cli.Context, op cli.Op) (cli.State, string, error) { return run(c, op, false) },
			Resume: func(c *cli.Context, op cli.Op) (cli.State, string, error) { return run(c, op, true) },
		}
	}
}

// writeState is the op state of a write as the server shows it.
func writeState(p control.VaultWritePlan) (cli.State, string) {
	if p.Write == nil {
		return cli.Sending, "not prepared on the server"
	}
	switch p.Write.Status {
	case "Published":
		return cli.Done, "stored"
	case "Abandoned", "NotApplied", "Invalid":
		return cli.Failed, strings.ToLower(p.Write.Status)
	}
	return cli.Accepted, strings.ToLower(p.Write.Status)
}

// fileValues is --file KEY=PATH, repeated.
type fileValues map[string]string

func (f *fileValues) String() string { return "" }
func (f *fileValues) Set(v string) error {
	key, path, ok := strings.Cut(v, "=")
	if !ok || path == "" || validSecretKey(key) != nil {
		return errors.New("needs KEY=PATH")
	}
	if *f == nil {
		*f = fileValues{}
	}
	if _, dup := (*f)[key]; dup {
		return errors.New("the same key twice")
	}
	(*f)[key] = path
	return nil
}

func stdinTerminal(c *cli.Context) bool {
	f, ok := c.In.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// promptHidden asks on the terminal without echo.
func promptHidden(c *cli.Context, question string) ([]byte, error) {
	tty, err := openPromptTerminal()
	if err != nil {
		return nil, errors.New("no terminal to ask on")
	}
	defer tty.Close()
	fmt.Fprint(c.Err, question)
	v, err := identity.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(c.Err)
	return v, err
}

func readLimited(r io.Reader, limit int) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(r, int64(limit+1)))
	if err != nil || len(raw) > limit {
		clear(raw)
		return nil, fmt.Errorf("the value is larger than %d bytes", limit)
	}
	return raw, nil
}

func readSecretFile(path string, limit int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if info, err := f.Stat(); err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	return readLimited(f, limit)
}

// secretValues reads the values of q's keys: from --file, from standard
// input when it is not a terminal and only one key is left, or from a
// hidden prompt.
func (g *globals) secretValues(c *cli.Context, files fileValues, q secrets.WriteRequest) (values map[string][]byte, err error) {
	values = map[string][]byte{}
	defer func() {
		if err != nil {
			for _, v := range values {
				clear(v)
			}
			values = nil
		}
	}()
	total := 0
	left := []string{}
	for _, key := range q.Keys {
		path, ok := files[key]
		if !ok {
			left = append(left, key)
			continue
		}
		v, err := readSecretFile(path, maxSecretBytes-total)
		if err != nil {
			return nil, err
		}
		values[key], total = v, total+len(v)
	}
	for key := range files {
		if !slices.Contains(q.Keys, key) {
			return nil, fmt.Errorf("secret %s has no key %s", q.Object, key)
		}
	}
	if len(left) == 0 {
		return values, nil
	}
	if !stdinTerminal(c) {
		if len(left) > 1 {
			return nil, cli.Usagef("standard input holds one value; give the others with --file KEY=PATH (left: %s)", strings.Join(left, ", "))
		}
		v, err := readLimited(c.In, maxSecretBytes-total)
		if err != nil {
			return nil, err
		}
		if len(v) == 0 {
			return nil, cli.Usagef("no value for %s on standard input", left[0])
		}
		values[left[0]] = v
		return values, nil
	}
	if g.noInput {
		return nil, cli.Usagef("no value for %s: give --file KEY=PATH or standard input", strings.Join(left, ", "))
	}
	for _, key := range left {
		v, err := promptHidden(c, fmt.Sprintf("Value of %s %s: ", q.Object, key))
		if err != nil {
			return nil, err
		}
		if total += len(v); total > maxSecretBytes {
			clear(v)
			return nil, fmt.Errorf("the values are larger than %d bytes", maxSecretBytes)
		}
		values[key] = v
	}
	return values, nil
}

// groupVerifier reads a group password (one line) and returns the
// verifier the writer node stores. The password itself is never sent.
func (g *globals) groupVerifier(c *cli.Context, file, group string) (map[string][]byte, error) {
	var raw []byte
	var err error
	switch {
	case file != "":
		raw, err = readSecretFile(file, 1025)
	case !stdinTerminal(c):
		raw, err = readLimited(c.In, 1025)
	case g.noInput:
		return nil, cli.Usagef("no password: give --password-file or standard input")
	default:
		raw, err = promptHidden(c, fmt.Sprintf("New password for group %s: ", group))
		if err == nil {
			again, e := promptHidden(c, "Again: ")
			if e != nil || !bytes.Equal(raw, again) {
				clear(again)
				clear(raw)
				return nil, errors.New("the passwords differ")
			}
			clear(again)
		}
	}
	defer clear(raw)
	if err != nil {
		return nil, err
	}
	password := bytes.TrimSuffix(raw, []byte{'\n'})
	if len(password) == 0 || len(password) > 1024 || bytes.ContainsAny(password, "\r\n\x00") {
		return nil, cli.Usagef("the password is one line of 1 to 1024 bytes")
	}
	var salt [16]byte
	if _, err = rand.Read(salt[:]); err != nil {
		return nil, err
	}
	hash, err := identity.PasswordHash(password, salt[:], identity.DefaultPasswordCost())
	clear(salt[:])
	if err != nil {
		return nil, err
	}
	v, err := hash.ProtectedBytes()
	if err != nil {
		return nil, err
	}
	return map[string][]byte{"verifier": v}, nil
}

func sameJSON(a, b any) bool {
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	return bytes.Equal(left, right)
}

func secretPhaseID(realm, id, phase string) string {
	return "secret-write/" + realm + "/" + id + "/" + phase
}

// startSecretWrite plans a new write (or finds the one this ID already
// started), confirms, records the op and follows the write.
func (g *globals) startSecretWrite(c *cli.Context, s *session, f *changeFlags, realm string, q control.VaultWritePlanRequest, impact, summary string, values func(secrets.WriteRequest) (map[string][]byte, error)) error {
	q.Realm, q.ID = realm, f.id.Get()
	intent, err := userauth.LoadSecretWrite(s.Home, s.Client, s.Stored.Session, realm, q.ID)
	switch {
	case err == nil:
		if intent.Request.Object != q.Object || intent.Request.Kind != q.Kind {
			return cli.ExitError{Code: 1, Err: fmt.Errorf("operation %s is already used by another write", q.ID)}
		}
		fmt.Fprintf(c.Err, "Continuing write %s.\n", q.ID)
		return g.finishSecretWrite(c, s, intent, true, values)
	case !errors.Is(err, userauth.ErrOperationMissing):
		return err
	}
	ctx, cancel := g.Deadline(c)
	plan, err := s.Client.PlanVaultWrite(ctx, s.Target, s.Stored.Session, q)
	cancel()
	if err != nil {
		return err
	}
	if plan.Write != nil {
		// A write this computer has no record of, for example one started
		// before the local state was lost: follow it to its end, but never
		// send values for it.
		if plan.Request.Object != q.Object || plan.Request.Kind != q.Kind {
			return cli.ExitError{Code: 1, Err: fmt.Errorf("write %s already exists on the server for %s; pick another --id", q.ID, plan.Request.Object)}
		}
		fmt.Fprintf(c.Err, "Write %s was started elsewhere; following it without sending values again.\n", q.ID)
		if err = g.recordRealm(s, "secret-write", summary, q.ID, realm); err != nil {
			return err
		}
		ctx, cancel = g.Deadline(c)
		window, err := s.Client.Whoami(ctx, s.Target, s.Stored.Session)
		cancel()
		if err != nil {
			return err
		}
		if intent, err = userauth.StageSecretWrite(s.Home, s.Client, s.Stored.Session, plan, max(1, window.ModuleEpoch), true); err != nil {
			return err
		}
		return g.finishSecretWrite(c, s, intent, true, func(secrets.WriteRequest) (map[string][]byte, error) {
			return nil, errors.New("this write was started elsewhere; its values are not sent again")
		})
	}
	ok, err := g.confirm(c, f, impact)
	if !ok || err != nil {
		return err
	}
	// Read the values before anything is sent, so a missing value leaves
	// nothing half done.
	given, err := values(plan.Request)
	if err != nil {
		return err
	}
	defer func() {
		for _, v := range given {
			clear(v)
		}
	}()
	once := func(secrets.WriteRequest) (map[string][]byte, error) {
		out := map[string][]byte{}
		for k, v := range given {
			out[k] = bytes.Clone(v)
		}
		return out, nil
	}
	if err = g.recordRealm(s, "secret-write", summary, q.ID, realm); err != nil {
		return err
	}
	ctx, cancel = g.Deadline(c)
	window, err := s.Client.Whoami(ctx, s.Target, s.Stored.Session)
	cancel()
	if err != nil {
		g.settle(q.ID, cli.Failed, "not sent: "+err.Error())
		return err
	}
	if intent, err = userauth.StageSecretWrite(s.Home, s.Client, s.Stored.Session, plan, max(1, window.ModuleEpoch), false); err != nil {
		g.settle(q.ID, cli.Failed, "not sent: "+err.Error())
		return err
	}
	fmt.Fprintf(c.Err, "Operation %s.\n", q.ID)
	return g.finishSecretWrite(c, s, intent, false, once)
}

func (g *globals) recordRealm(s *session, kind, summary, id, realm string) error {
	x, err := openOps()
	if err != nil {
		return err
	}
	defer x.Close()
	return x.Add(cli.Op{ID: id, Kind: kind, Context: s.Context, Tenant: realm, Summary: summary})
}

func (g *globals) finishSecretWrite(c *cli.Context, s *session, intent userauth.SecretWriteIntent, resume bool, values func(secrets.WriteRequest) (map[string][]byte, error)) error {
	plan, err := g.runSecretWrite(c, s, intent, resume, values)
	if err != nil {
		return err
	}
	st, detail := writeState(plan)
	g.settle(intent.Request.ID, st, detail)
	switch st {
	case cli.Done:
		fmt.Fprintln(c.Err, "Stored.")
		return nil
	case cli.Failed:
		return cli.ExitError{Code: 3, Err: fmt.Errorf("the write ended as %s", detail)}
	}
	return cli.ExitError{Code: exitUnknown, Err: fmt.Errorf("the write is %s; check it with 'sfcli op show %s'", detail, intent.Request.ID)}
}

// runSecretWrite takes a saved write through its steps. resume resends a
// step whose reply was lost; values are asked only when the write still has
// to send them.
func (g *globals) runSecretWrite(c *cli.Context, s *session, intent userauth.SecretWriteIntent, resume bool, values func(secrets.WriteRequest) (map[string][]byte, error)) (control.VaultWritePlan, error) {
	ctx, cancel := context.WithTimeout(c.Ctx, 4*g.timeout)
	defer cancel()
	var plan control.VaultWritePlan
	refresh := func() error {
		var err error
		plan, err = s.Client.PlanVaultWrite(ctx, s.Target, s.Stored.Session, control.VaultWritePlanRequest{Realm: intent.Realm, ID: intent.Request.ID})
		if err == nil && plan.Write == nil {
			plan.Request = intent.Request
		}
		if err == nil && plan.Write != nil && !sameJSON(plan.Request, intent.Request) {
			return errors.New("the write on the server is not the saved one")
		}
		return err
	}
	unknownErr := func(err error) error {
		return cli.ExitError{Code: exitUnknown, Err: fmt.Errorf("%w; continue with 'sfcli op resume %s'", err, intent.Request.ID)}
	}
	phase := func(name, action string, expected uint64, payload any) error {
		id := secretPhaseID(intent.Realm, intent.Request.ID, name)
		if old, err := userauth.LoadOperation(s.Home, s.Client, s.Stored.Session, id); err == nil {
			expected = old.Operation.Change.Expected
		} else if !errors.Is(err, userauth.ErrOperationMissing) {
			return err
		}
		result, err := managementMutation(ctx, s.Client, s.Target, s.Stored, s.Home, id, action, expected, intent.Epoch, payload, resume)
		if err != nil {
			return unknownErr(err)
		}
		if result.Code != state.Applied {
			return cli.ExitError{Code: 3, Err: fmt.Errorf("the server refused to %s the write: %v", name, result.Code)}
		}
		if err = refresh(); err != nil {
			return unknownErr(err)
		}
		return nil
	}
	if err := refresh(); err != nil {
		return plan, err
	}
	if plan.Write == nil {
		if err := phase("prepare", "vault-prepare-write", intent.ExpectedTree, control.VaultWrite{Realm: intent.Realm, Request: intent.Request}); err != nil {
			return plan, err
		}
		if plan.Write == nil {
			return plan, unknownErr(errors.New("the prepared write is not visible yet"))
		}
	}
	if plan.Write.Status == "Prepared" {
		if err := phase("dispatch", "vault-dispatch-write", plan.TreeRevision, control.VaultWriteAction{Realm: intent.Realm, ID: intent.Request.ID, Epoch: intent.Request.Epoch}); err != nil {
			return plan, err
		}
	}
	switch plan.Write.Status {
	case "Published", "Abandoned", "NotApplied", "Invalid":
		return plan, nil
	}
	save := func(next userauth.SecretWriteIntent) error {
		if err := userauth.ReplaceSecretWrite(s.Home, s.Client, s.Stored.Session, intent, next); err != nil {
			return err
		}
		intent = next
		return nil
	}
	if intent.Pending == nil && (plan.Write.Status == "Dispatched" || plan.Write.Status == "Unknown") {
		candidates := []config.Peer{}
		switch {
		case len(plan.Voters) > 0 && intent.Writer != ([32]byte{}):
			// A builtin write keeps the voter that took its values.
			for _, v := range plan.Voters {
				if v.Key == hex.EncodeToString(intent.Writer[:]) {
					candidates = append(candidates, v)
				}
			}
			if len(candidates) == 0 {
				return plan, unknownErr(errors.New("the voter that took the values is not a voter now"))
			}
		case len(plan.Voters) > 0 && !intent.Attempted:
			candidates = plan.Voters
		case plan.Receiver != nil:
			candidates = append(candidates, *plan.Receiver)
		default:
			return plan, unknownErr(errors.New("the Vault profile has no writer node now"))
		}
		pins := map[sfcp.Identity]sfcp.Peer{}
		for _, p := range s.Client.Peers {
			pins[p.Key] = p
		}
		peers := []sfcp.Peer{}
		for _, c := range candidates {
			key, err := identity.ParseKey(c.Key)
			if err != nil {
				return plan, err
			}
			peer := sfcp.Peer{ID: c.ID, Endpoint: c.Endpoint, Policy: sfcp.Policy{Key: sfcp.Identity(key), Respond: true}}
			pins[peer.Key] = peer
			peers = append(peers, peer)
		}
		remote := s.Client
		var err error
		remote.Mesh, err = sfcp.NewTransport(s.Client.Self, s.Client.Cluster, func(k sfcp.Identity) (sfcp.Peer, bool) { p, ok := pins[k]; return p, ok })
		if err != nil {
			return plan, err
		}
		defer remote.Mesh.Close()
		peer := peers[0]
		if len(peers) > 1 {
			// Pick a voter this client reaches before any value is sent.
			peer = sfcp.Peer{}
			for _, p := range peers {
				dial, cancel := context.WithTimeout(ctx, g.timeout/2)
				_, err := remote.Mesh.Dial(dial, p)
				cancel()
				if err == nil {
					peer = p
					break
				}
			}
			if peer.Key == (sfcp.Identity{}) {
				return plan, cli.ExitError{Code: 3, Err: errors.New("no voter answered; nothing was sent")}
			}
		}
		q := userauth.SecretRequest{Realm: intent.Realm, ID: intent.Request.ID, Mode: "recover"}
		if !intent.Attempted && plan.Write.Status == "Dispatched" {
			if q.Values, err = values(intent.Request); err != nil {
				return plan, err
			}
			defer func() {
				for _, v := range q.Values {
					clear(v)
				}
			}()
			if ctx.Err() != nil {
				return plan, unknownErr(ctx.Err())
			}
			q.Mode = "execute"
		}
		if !intent.Attempted {
			next := intent
			next.Attempted = true
			if len(plan.Voters) > 0 {
				next.Writer = [32]byte(peer.Key)
			}
			if err = save(next); err != nil {
				return plan, unknownErr(err)
			}
		}
		reply, err := remote.WriteVault(ctx, peer, s.Stored.Session, q)
		if reply.VaultObservation == nil {
			why := "reply " + reply.Code
			if err != nil {
				why = err.Error()
			}
			return plan, unknownErr(fmt.Errorf("the writer node %s did not say what it stored (%s); its daemon log says why", plan.Receiver.ID, why))
		}
		fact := reply.VaultObservation
		if fact.Cluster != s.Client.Cluster || fact.Tenant != intent.Realm || !sameJSON(fact.Request, intent.Request) || fact.Generation != plan.Write.Generation || fact.Operation != plan.Write.Operation {
			return plan, unknownErr(sfcp.ErrFrame)
		}
		next := intent
		next.Sequence++
		next.Pending = fact
		if err = save(next); err != nil {
			return plan, unknownErr(err)
		}
	}
	if intent.Pending != nil {
		if !sameJSON(plan.Observation, intent.Pending) {
			if err := phase(fmt.Sprintf("observe-%d", intent.Sequence), "vault-observe-write", plan.TreeRevision, control.VaultObserve{Observation: *intent.Pending}); err != nil {
				return plan, err
			}
		}
		next := intent
		next.Pending = nil
		if err := save(next); err != nil {
			return plan, unknownErr(err)
		}
	}
	if plan.Write.Status == "StoredUnreferenced" {
		if err := phase("publish", "vault-publish-write", plan.TreeRevision, control.VaultWriteAction{Realm: intent.Realm, ID: intent.Request.ID, Epoch: intent.Request.Epoch, ObjectRevision: plan.Write.ExpectedObjectRevision}); err != nil {
			return plan, err
		}
	}
	return plan, nil
}

func secretPutCommand(g *globals) *cli.Command {
	var v vaultScope
	var f changeFlags
	var files fileValues
	return &cli.Command{
		Name:  "put",
		Args:  "NAME [KEY...]",
		Short: "Write values of a secret to the external Vault",
		Long: `Writes the named keys (all keys of the secret when none are named). Each
value comes from --file KEY=PATH, or from standard input when it is not a
terminal and one key is left, or else from a hidden prompt. Values are raw
bytes; nothing is trimmed. The object in the external Vault is replaced:
keys not named are left out of it.

If the reply is lost, run 'sfcli op resume ID': a value that may have reached
the writer node is never sent again.`,
		Flags: func(fs *flag.FlagSet) {
			v.register(fs)
			f.register(fs, false, true)
			fs.Var(&files, "file", "read the value of `KEY=PATH` from a file (repeat)")
		},
		Run: func(c *cli.Context, args []string) error {
			if len(args) == 0 {
				return cli.Usagef("put needs the secret name and optionally its keys")
			}
			if err := validSecretID("secret", args[0]); err != nil {
				return err
			}
			keys := args[1:]
			for _, k := range keys {
				if err := validSecretKey(k); err != nil {
					return err
				}
			}
			s, realm, err := g.secretSession(c, v)
			if err != nil {
				return err
			}
			defer s.Close()
			_, o, err := g.vaultObject(c, s, realm, args[0])
			if err != nil {
				return err
			}
			if o.Kind != secrets.Secret {
				return cli.Usagef("%s is a group; set its password with 'sfcli secret group password'", args[0])
			}
			if len(keys) == 0 {
				keys = slices.Clone(o.Reference.Keys)
			}
			slices.Sort(keys)
			for _, k := range keys {
				if !slices.Contains(o.Reference.Keys, k) {
					return cli.Usagef("secret %s has no key %s (it has %s)", args[0], k, strings.Join(o.Reference.Keys, ", "))
				}
			}
			q := control.VaultWritePlanRequest{Object: args[0], Kind: secrets.ValueWrite, Keys: keys}
			return g.startSecretWrite(c, s, &f, realm, q,
				fmt.Sprintf("Write %s of secret %s in %s.", strings.Join(keys, ", "), args[0], realmName(realm)),
				"secret put "+args[0]+" "+strings.Join(keys, " ")+scopeSummary(realm),
				func(r secrets.WriteRequest) (map[string][]byte, error) { return g.secretValues(c, files, r) })
		},
	}
}

func secretPasswordCommand(g *globals) *cli.Command {
	var v vaultScope
	var f changeFlags
	var profile, file string
	return &cli.Command{
		Name:  "password",
		Args:  "GROUP",
		Short: "Set the password that approves apps using a group",
		Long: `Reads the new password from --password-file, from standard input when it
is not a terminal, or from a hidden prompt (asked twice). Only a verifier
of it is stored. --profile names the writer profile the first time.`,
		Flags: func(fs *flag.FlagSet) {
			v.register(fs)
			f.register(fs, false, true)
			fs.StringVar(&profile, "profile", "", "writer `profile` for the verifier (first time only)")
			fs.StringVar(&file, "password-file", "", "read the password from this `file`")
		},
		Run: func(c *cli.Context, args []string) error {
			if err := secretArgs(args, 1, "group password needs one group name"); err != nil {
				return err
			}
			s, realm, err := g.secretSession(c, v)
			if err != nil {
				return err
			}
			defer s.Close()
			q := control.VaultWritePlanRequest{Object: args[0], Kind: secrets.VerifierWrite, Profile: profile}
			return g.startSecretWrite(c, s, &f, realm, q,
				fmt.Sprintf("Set the password of group %s in %s. Approvals made with the old password stop working.", args[0], realmName(realm)),
				"secret group password "+args[0]+scopeSummary(realm),
				func(secrets.WriteRequest) (map[string][]byte, error) { return g.groupVerifier(c, file, args[0]) })
		},
	}
}

func secretWriteCommand(g *globals) *cli.Command {
	var v vaultScope
	list := &cli.Command{
		Name:  "list",
		Short: "List writes and where they stand",
		Flags: v.register,
		Run: func(c *cli.Context, args []string) error {
			if len(args) != 0 {
				return cli.Usagef("write list takes no arguments")
			}
			s, realm, err := g.secretSession(c, v)
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			t, err := readVaultTree(ctx, s, realm)
			cancel()
			if err != nil {
				return err
			}
			writes := []control.VaultWriteView{}
			for _, r := range t.rows {
				if r.Write != nil {
					writes = append(writes, *r.Write)
				}
			}
			return cli.Print(c.Out, g.output.Format(), writes, func() cli.Rows {
				rows := cli.Rows{Header: []string{"id", "secret", "kind", "keys", "status", "by"}}
				for _, w := range writes {
					rows.Add(w.Request.ID, w.Request.Object, w.Request.Kind, strings.Join(w.Request.Keys, ","), w.Status, strings.TrimPrefix(w.Actor, "user/"))
				}
				return rows
			})
		},
	}
	var fa, fc changeFlags
	var va, vc vaultScope
	abandon := &cli.Command{
		Name:  "abandon",
		Args:  "ID",
		Short: "Give up a write that was not stored",
		Long:  `A write that the writer node may still be storing must settle first ('sfcli op resume ID').`,
		Flags: func(fs *flag.FlagSet) { va.register(fs); fa.register(fs, false, true) },
		Run: func(c *cli.Context, args []string) error {
			if len(args) != 1 || validSecretID("write", args[0]) != nil {
				return cli.Usagef("write abandon needs one write ID")
			}
			s, realm, err := g.secretSession(c, va)
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			t, err := readVaultTree(ctx, s, realm)
			cancel()
			if err != nil {
				return err
			}
			w, ok := t.write(args[0])
			if !ok {
				return fmt.Errorf("%s has no write %s", realmName(realm), args[0])
			}
			return g.vaultChange(c, s, &fa, fmt.Sprintf("Give up write %s of %s (%s).", args[0], w.Request.Object, w.Status),
				"secret write abandon "+args[0]+scopeSummary(realm), "vault-abandon-write", t.tree, control.VaultWriteAction{Realm: realm, ID: args[0], Epoch: t.epoch})
		},
	}
	clearCmd := &cli.Command{
		Name:  "clear",
		Short: "Forget the finished writes of the tree",
		Long:  `Every write must be finished (stored or abandoned). The stored values stay.`,
		Flags: func(fs *flag.FlagSet) { vc.register(fs); fc.register(fs, false, true) },
		Run: func(c *cli.Context, args []string) error {
			if len(args) != 0 {
				return cli.Usagef("write clear takes no arguments")
			}
			s, realm, err := g.secretSession(c, vc)
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			t, err := readVaultTree(ctx, s, realm)
			cancel()
			if err != nil {
				return err
			}
			return g.vaultChange(c, s, &fc, fmt.Sprintf("Forget the finished writes of %s.", realmName(realm)),
				"secret write clear"+scopeSummary(realm), "vault-rotate-writes", t.tree, control.VaultWriteAction{Realm: realm, Epoch: t.epoch})
		},
	}
	return &cli.Command{
		Name:  "write",
		Short: "Value and password writes: list, abandon, clear",
		Sub:   []*cli.Command{list, abandon, clearCmd},
	}
}
