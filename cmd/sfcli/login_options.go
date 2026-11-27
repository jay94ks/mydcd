// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"flag"
	"io"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cliprofile"
)

// loginOptions contains syntax and selection only. Parsing never opens the
// wallet, key files, credential descriptors or a network connection.
type loginOptions struct {
	username, keyFile, keyName string
	approvalKey                string
	method                     access.Method
	credentialID               string
	passwordStdin, tokenStdin  bool
	userID, requestID          string
	account                    accountOptions
}

// Flag parsing has already emitted its diagnostic; preserve the CLI's exit 2
// without printing a second error for those failures or trailing arguments.
var errLoginFlags = errors.New("invalid login flags")

func parseLoginOptions(args []string, account accountOptions, diagnostic io.Writer) (loginOptions, error) {
	if len(args) == 0 || args[0] != "login" && args[0] != "enroll-admin" {
		return loginOptions{}, errLoginFlags
	}
	login := args[0] == "login"
	enroll := args[0] == "enroll-admin"
	var passwordStdin, tokenStdin bool
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(diagnostic)
	var user, userAlias, key, namedKey, auth onceString
	flags.Var(&user, "username", "registered username")
	flags.Var(&userAlias, "user", "registered username (same account as global --user)")
	flags.Var(&auth, "method", "password, private-key or token")
	flags.Var(&key, "key-file", "private PKCS8 Ed25519 PEM file")
	flags.Var(&namedKey, "key", "named private key in the unlocked wallet")
	flags.Var(&account.Password, "wallet-password-fd", "protected wallet password descriptor")
	flags.BoolVar(&account.NoInput, "no-input", account.NoInput, "never prompt for credentials")
	var id, request onceString
	var credential onceString
	var approvalKey onceString
	if login {
		flags.Var(&approvalKey, "approval-key", "explicit named user key for password/token session approval")
		flags.Var(&credential, "credential", "credential ID (required if the method is ambiguous)")
		flags.BoolVar(&passwordStdin, "password-stdin", false, "read one password from stdin")
		flags.BoolVar(&tokenStdin, "token-stdin", false, "read one opaque token from stdin")
	}
	if enroll {
		flags.Var(&id, "user-id", "initial stable user ID")
		flags.Var(&request, "request-id", "original enrollment request ID")
	}
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		return loginOptions{}, errLoginFlags
	}

	if user.set && userAlias.set && user.value != userAlias.value {
		return loginOptions{}, cliprofile.ErrSelection
	}
	if !user.set {
		user.value = userAlias.value
	}
	if account.User != "" && user.value != "" && account.User != user.value {
		return loginOptions{}, cliprofile.ErrSelection
	}
	if user.value == "" {
		user.value = account.User
	}
	if login && auth.value == "private-key" && !key.set && !namedKey.set && account.Target.WalletKey != "" {
		namedKey.value = account.Target.WalletKey
		namedKey.set = true
	}
	if !cliprofile.ValidUsername(user.value) || namedKey.set && !cliprofile.ValidKeyName(namedKey.value) {
		return loginOptions{}, cliprofile.ErrInput
	}
	if approvalKey.set && (!cliprofile.ValidKeyName(approvalKey.value) || auth.value != "password" && auth.value != "token") {
		return loginOptions{}, errors.New("--approval-key requires password/token login and an explicit wallet key name")
	}
	hasKey := (key.value != "") != (namedKey.value != "")
	validLogin := auth.value == "private-key" && hasKey && credential.value == "" && !passwordStdin && !tokenStdin || auth.value == "password" && !key.set && !namedKey.set && !tokenStdin || auth.value == "token" && !key.set && !namedKey.set && !passwordStdin

	if user.value == "" || login && !validLogin || enroll && (!hasKey || auth.value != "" || id.value == "" || request.value == "") {
		if enroll {
			return loginOptions{}, errors.New("enroll-admin requires --user-id, --username/--user, --key/--key-file and the original --request-id")
		}
		return loginOptions{}, errors.New("login requires --user/--username and an explicit method with matching key/key-file/password-stdin/token-stdin options")
	}
	return loginOptions{
		username: user.value, keyFile: key.value, keyName: namedKey.value,
		method: access.Method(auth.value), credentialID: credential.value,
		approvalKey:   approvalKey.value,
		passwordStdin: passwordStdin, tokenStdin: tokenStdin,
		userID: id.value, requestID: request.value, account: account,
	}, nil
}
