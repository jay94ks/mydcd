// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strconv"

	"github.com/jay94ks/mydcd/internal/cliprofile"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/wallet"
	"golang.org/x/sys/unix"
)

type walletFD struct {
	value int
	set   bool
}

func (f *walletFD) String() string {
	if !f.set {
		return ""
	}
	return strconv.Itoa(f.value)
}
func (f *walletFD) Set(raw string) error {
	n, e := strconv.Atoi(raw)
	if f.set || e != nil || n < 3 || n > 1<<20 {
		return errors.New("protected wallet descriptor must occur once and be at least 3")
	}
	f.value = n
	f.set = true
	return nil
}

type walletOptions struct {
	action                         string
	name, keyFile                  onceString
	password, newPassword, confirm walletFD
	noInput, abort                 bool
}

func walletUsage(out io.Writer) {
	fmt.Fprintln(out, "mydc wallet init [--wallet-password-fd FD --wallet-confirm-fd FD]")
	fmt.Fprintln(out, "mydc wallet generate --name NAME | import --name NAME --key-file PRIVATE.pem | list | public NAME")
	fmt.Fprintln(out, "mydc wallet passwd [--wallet-password-fd FD --new-wallet-password-fd FD --wallet-confirm-fd FD]")
	fmt.Fprintln(out, "mydc wallet status | recover [--abort]")
	fmt.Fprintln(out, "Wallet commands use the Linux user's ~/.mydc independently of client configuration. Passwords use hidden TTY or distinct explicit FDs >=3; --no-input or MYDC_NONINTERACTIVE=1 forbids TTY prompts. No private key/password output.")
}
func parseWalletOptions(args []string, diagnostic io.Writer) (walletOptions, error) {
	var o walletOptions
	if len(args) == 0 {
		return o, errors.New("wallet requires a subcommand")
	}
	o.action = args[0]
	args = args[1:]
	if o.action == "public" && len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		if o.name.Set(args[0]) != nil {
			return o, errors.New("invalid key name")
		}
		args = args[1:]
	}
	f := flag.NewFlagSet("wallet "+o.action, flag.ContinueOnError)
	f.SetOutput(diagnostic)
	f.Usage = func() { walletUsage(diagnostic) }
	f.Var(&o.name, "name", "case-sensitive wallet key name")
	f.Var(&o.keyFile, "key-file", "private PKCS8 Ed25519 PEM file")
	f.Var(&o.password, "wallet-password-fd", "protected current password descriptor")
	f.Var(&o.newPassword, "new-wallet-password-fd", "protected new password descriptor")
	f.Var(&o.confirm, "wallet-confirm-fd", "protected new password confirmation descriptor")
	f.BoolVar(&o.noInput, "no-input", false, "never prompt")
	f.BoolVar(&o.abort, "abort", false, "abort a staged update only before publication")
	if e := f.Parse(args); e != nil {
		return o, e
	}
	if len(f.Args()) != 0 {
		return o, errors.New("unexpected wallet positional arguments")
	}
	switch o.action {
	case "init", "passwd", "list", "status", "recover":
		if o.name.set || o.keyFile.set {
			return o, errors.New("unexpected wallet key option")
		}
	case "generate", "public":
		if !o.name.set || !cliprofile.ValidKeyName(o.name.value) || o.keyFile.set {
			return o, errors.New("wallet requires a valid key name")
		}
	case "import":
		if !o.name.set || !cliprofile.ValidKeyName(o.name.value) || !o.keyFile.set {
			return o, errors.New("wallet import requires name and private key file")
		}
	default:
		return o, errors.New("unknown wallet command")
	}
	if o.abort && o.action != "recover" || o.newPassword.set && o.action != "passwd" || o.confirm.set && o.action != "init" && o.action != "passwd" {
		return o, errors.New("wallet option does not apply to this command")
	}
	if (o.action == "status" || o.action == "recover") && (o.password.set || o.newPassword.set || o.confirm.set) {
		return o, errors.New("wallet recovery uses the original encrypted intent, not a new password")
	}
	seen := map[int]bool{}
	for _, fd := range []walletFD{o.password, o.newPassword, o.confirm} {
		if fd.set {
			if seen[fd.value] {
				return o, errors.New("password roles require distinct descriptors")
			}
			seen[fd.value] = true
		}
	}
	return o, nil
}
func readWalletPassword(fd walletFD, noInput bool, label string, diagnostic io.Writer) ([]byte, error) {
	if !fd.set {
		if password, ok, err := walletPasswordFromEnv(); ok || err != nil {
			return password, err
		}
	}
	if fd.set {
		raw, e := readSecretDescriptor(fd.value, 1025)
		if e != nil {
			return nil, identity.ErrCredential
		}
		value := bytes.TrimSuffix(raw, []byte{'\n'})
		if len(value) < 1 || len(value) > 1024 || bytes.ContainsAny(value, "\r\n\x00") {
			clear(raw)
			return nil, identity.ErrCredential
		}
		return value, nil
	}
	if noInput || nonInteractiveEnv() {
		return nil, errors.New("wallet password requires an explicit protected descriptor")
	}
	tty, e := openPromptTerminal()
	if e != nil {
		return nil, errors.New("wallet password requires a hidden terminal or explicit protected descriptor")
	}
	defer tty.Close()
	_, _ = fmt.Fprint(diagnostic, label+": ")
	value, e := identity.ReadPassword(int(tty.Fd()))
	_, _ = fmt.Fprintln(diagnostic)
	if e != nil || bytes.ContainsAny(value, "\r\n\x00") {
		clear(value)
		return nil, identity.ErrCredential
	}
	return value, nil
}
func walletFailure(diagnostic io.Writer, err error) int {
	code := 1
	if errors.Is(err, wallet.ErrPending) {
		code = 4
	}
	return failure(diagnostic, err, code)
}
func walletOutput(out, diagnostic io.Writer, value any) int {
	if e := json.NewEncoder(out).Encode(value); e != nil {
		return failure(diagnostic, errors.New("wallet output failed; inspect wallet status before another update"), 1)
	}
	return 0
}
func runWallet(args []string, out, diagnostic io.Writer) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		walletUsage(out)
		return 0
	}
	o, e := parseWalletOptions(args, diagnostic)
	if errors.Is(e, flag.ErrHelp) {
		return 0
	}
	if e != nil {
		return failure(diagnostic, e, 2)
	}
	home, e := os.UserHomeDir()
	if e != nil {
		return failure(diagnostic, e, 2)
	}
	disk, e := wallet.OpenDisk(home, o.action == "init")
	if e != nil {
		if o.action == "status" && errors.Is(e, fs.ErrNotExist) {
			return walletOutput(out, diagnostic, wallet.Status{})
		}
		return walletFailure(diagnostic, e)
	}
	defer disk.Close()
	status, e := disk.Status()
	if e != nil {
		return walletFailure(diagnostic, e)
	}
	if o.action == "status" {
		return walletOutput(out, diagnostic, status)
	}
	if o.action == "recover" {
		if e = disk.Recover(o.abort); e != nil {
			return walletFailure(diagnostic, e)
		}
		status, e = disk.Status()
		if e != nil {
			return walletFailure(diagnostic, e)
		}
		return walletOutput(out, diagnostic, status)
	}
	if status.Pending || status.UnpublishedCandidate {
		return walletFailure(diagnostic, wallet.ErrPending)
	}
	if o.action == "init" && status.Exists {
		return walletFailure(diagnostic, wallet.ErrExists)
	}
	if o.action != "init" && !status.Exists {
		return walletFailure(diagnostic, wallet.ErrMissing)
	}
	password, e := readWalletPassword(o.password, o.noInput, "Wallet password", diagnostic)
	if e != nil {
		return failure(diagnostic, e, 2)
	}
	defer clear(password)
	if o.action == "init" {
		confirm, e := readWalletPassword(o.confirm, o.noInput, "Confirm wallet password", diagnostic)
		if e != nil {
			return failure(diagnostic, e, 2)
		}
		defer clear(confirm)
		if subtle.ConstantTimeCompare(password, confirm) != 1 {
			return failure(diagnostic, errors.New("wallet passwords do not match"), 2)
		}
		if e = disk.Init(password); e != nil {
			return walletFailure(diagnostic, e)
		}
		return walletOutput(out, diagnostic, map[string]any{"schema": 1, "status": "initialized"})
	}
	if e = disk.Unlock(password); e != nil {
		return walletFailure(diagnostic, e)
	}
	switch o.action {
	case "list":
		keys, e := disk.List()
		if e != nil {
			return walletFailure(diagnostic, e)
		}
		return walletOutput(out, diagnostic, keys)
	case "public":
		keys, err := disk.List()
		if err != nil {
			return walletFailure(diagnostic, err)
		}
		for _, key := range keys {
			if key.Name == o.name.value {
				return walletOutput(out, diagnostic, key)
			}
		}
		return walletFailure(diagnostic, wallet.ErrMissing)
	case "generate":
		key, e := disk.Generate(o.name.value)
		if e != nil {
			return walletFailure(diagnostic, e)
		}
		if e = disk.Save(password); e != nil {
			return walletFailure(diagnostic, e)
		}
		return walletOutput(out, diagnostic, key)
	case "import":
		key, e := identity.LoadPrivateKeyFile(o.keyFile.value)
		if e != nil {
			return walletFailure(diagnostic, e)
		}
		defer clear(key)
		seed := key.Seed()
		entry := wallet.Entry{Name: o.name.value}
		copy(entry.Seed[:], seed)
		clear(seed)
		defer clear(entry.Seed[:])
		changed, e := disk.Put(entry)
		if e != nil {
			return walletFailure(diagnostic, e)
		}
		if changed {
			if e = disk.Save(password); e != nil {
				return walletFailure(diagnostic, e)
			}
		}
		keys, err := disk.List()
		if err != nil {
			return walletFailure(diagnostic, err)
		}
		for _, key := range keys {
			if key.Name == entry.Name {
				return walletOutput(out, diagnostic, key)
			}
		}
		return walletFailure(diagnostic, wallet.ErrMissing)
	case "passwd":
		next, e := readWalletPassword(o.newPassword, o.noInput, "New wallet password", diagnostic)
		if e != nil {
			return failure(diagnostic, e, 2)
		}
		defer clear(next)
		confirm, e := readWalletPassword(o.confirm, o.noInput, "Confirm new wallet password", diagnostic)
		if e != nil {
			return failure(diagnostic, e, 2)
		}
		defer clear(confirm)
		if subtle.ConstantTimeCompare(next, confirm) != 1 {
			return failure(diagnostic, errors.New("wallet passwords do not match"), 2)
		}
		if e = disk.Save(next); e != nil {
			return walletFailure(diagnostic, e)
		}
		return walletOutput(out, diagnostic, map[string]any{"schema": 1, "status": "password-changed"})
	}
	return failure(diagnostic, errors.New("unknown wallet command"), 2)
}

// readSecretDescriptor reads at most limit bytes from an inherited file
// descriptor (the old --*-fd options of wallet, certificate and initial
// credential input).
func readSecretDescriptor(fd, limit int) ([]byte, error) {
	dup, err := unix.Dup(fd)
	if err != nil {
		return nil, identity.ErrCredential
	}
	f := os.NewFile(uintptr(dup), "protected-secret")
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, int64(limit+1)))
	if err != nil || len(raw) > limit {
		clear(raw)
		return nil, identity.ErrCredential
	}
	return raw, nil
}
