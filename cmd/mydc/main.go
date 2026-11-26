// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/jay94ks/mydcd/internal/cliprofile"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/identity"
	"io"
	"os"
	"time"
)

type onceString struct {
	value string
	set   bool
}

func (v *onceString) String() string { return v.value }
func (v *onceString) Set(s string) error {
	if v.set || s == "" {
		return errors.New("option must have a value and occur once")
	}
	v.value = s
	v.set = true
	return nil
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
func run(args []string, out, diagnostic io.Writer) int {
	if newCommand(args) {
		return runNew(args, out, diagnostic)
	}
	return runLegacy(args, out, diagnostic)
}

// runLegacy is the old command path. New commands that still use its flows
// call it directly (see account_cmd.go); it goes in the final cleanup.
func runLegacy(args []string, out, diagnostic io.Writer) int {
	flags := flag.NewFlagSet("mydc", flag.ContinueOnError)
	flags.SetOutput(diagnostic)
	var file, clusterName, tenantName, userName onceString
	var reasonText, incidentID, approvedBy onceString
	var version bool
	var peerID string
	var timeout time.Duration
	var accountPassword walletFD
	var noInput bool
	flags.Var(&reasonText, "reason", "signed operation display reason, maximum 512 characters")
	flags.Var(&incidentID, "incident-id", "signed operation incident label; no additional authority")
	flags.Var(&approvedBy, "approved-by", "claimed approval label only; never substitutes for an approval signature")
	flags.Var(&userName, "user", "saved username; required when multiple accounts coexist")
	flags.Var(&accountPassword, "wallet-password-fd", "protected wallet password descriptor for account commands")
	flags.BoolVar(&noInput, "no-input", false, "never prompt for wallet/login input")
	// The old commands never ask for confirmation; -y is accepted so the
	// global options stay the same as the new commands'.
	flags.Bool("y", false, "do not ask for confirmation (the old commands never ask)")
	flags.Var(&clusterName, "context", "context name (default: the current context)")
	flags.Var(&clusterName, "cluster", "same as --context")
	flags.Var(&tenantName, "tenant", "tenant ID (default: the context's tenant)")
	flags.Var(&file, "config", "client configuration file instead of a context")
	flags.BoolVar(&version, "version", false, "print version")
	flags.StringVar(&peerID, "peer", "", "configured target peer ID (default first)")
	flags.DurationVar(&timeout, "timeout", 15*time.Second, "request deadline")
	flags.Usage = func() {
		commandHelp(diagnostic)
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	args = flags.Args()
	var operationReason *control.OperationReason
	if reasonText.set || incidentID.set || approvedBy.set {
		reason := control.OperationReason{Text: reasonText.value, IncidentID: incidentID.value, ApprovedBy: approvedBy.value}
		allowed := len(args) > 0 && (args[0] == "manage" || args[0] == "standalone" || args[0] == "compose" || args[0] == "registry")
		if !allowed || !reason.Valid() {
			return failure(diagnostic, errors.New("invalid operation reason or unsupported command"), 2)
		}
		operationReason = &reason
	}

	if userName.set && !cliprofile.ValidUsername(userName.value) {
		return failure(diagnostic, cliprofile.ErrInput, 2)
	}
	if clusterName.set && (file.set || !cliprofile.ValidName(clusterName.value)) || tenantName.set && !cliprofile.ValidKeyName(tenantName.value) {
		return failure(diagnostic, cliprofile.ErrSelection, 2)
	}
	if version || len(args) == 1 && args[0] == "version" {
		fmt.Fprintln(out, "mydc 1")
		return 0
	}
	if len(args) == 3 && args[0] == "identity" && args[1] == "create" {
		if clusterName.set || tenantName.set || userName.set || accountPassword.set || noInput {
			return failure(diagnostic, cliprofile.ErrSelection, 2)
		}
		self, err := identity.Create(args[2])
		if err != nil {
			return failure(diagnostic, err, 1)
		}
		fmt.Fprintln(out, self.Actor())
		return 0
	}
	if len(args) == 0 {
		flags.Usage()
		return 2
	}
	if args[0] == "wallet" {
		if clusterName.set || tenantName.set || userName.set || accountPassword.set || noInput {
			return failure(diagnostic, errors.New("wallet options belong after the wallet subcommand"), 2)
		}
		return runWallet(args[1:], out, diagnostic)
	}
	if args[0] == "compose" {
		// Kept only for the flow tests and tests/kvm until the final
		// cleanup ports them; people use 'mydc app', which runs the same flows.
		fmt.Fprintln(diagnostic, "'mydc compose' is going away; use 'mydc app' (mydc app --help).")
	}
	if userHelp(args, diagnostic) {
		return 0
	}
	if timeout <= 0 || timeout > 5*time.Minute {
		return failure(diagnostic, errors.New("timeout must be in (0,5m]"), 2)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return failure(diagnostic, err, 2)
	}
	selected, err := resolveCommandProfile(home, clusterName.value, file.value, tenantName.value)
	if err != nil {
		return failure(diagnostic, err, 2)
	}
	c := selected.Client
	explicitTimeout := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "timeout" {
			explicitTimeout = true
		}
	})
	if !explicitTimeout && selected.Target.Timeout != 0 {
		timeout = selected.Target.Timeout
	}
	if peerID == "" {
		peerID = selected.Target.Peer
	}
	return runUserWithAccount(args, c, home, peerID, timeout, accountOptions{OperationReason: operationReason, User: userName.value, Password: accountPassword, NoInput: noInput, Target: selected.Target, TenantName: tenantName.value}, out, diagnostic)
}
func failure(out io.Writer, err error, code int) int { fmt.Fprintln(out, err); return code }
