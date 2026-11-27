// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cliprofile"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/internal/wallet"
)

func userHelp(args []string, out io.Writer) bool {
	if args[0] != "server-version" && args[0] != "service-call" && args[0] != "login" && args[0] != "whoami" && args[0] != "logout" && args[0] != "enroll-admin" && args[0] != "manage" && args[0] != "compose" {
		return false
	}
	for _, arg := range args[1:] {
		if arg == "-h" || arg == "--help" {
			if args[0] == "service-call" {
				serviceCallHelp(out)
				return true
			}
			if args[0] == "manage" {
				managementHelp(out)
				return true
			}
			fmt.Fprintln(out, "sfcli [--cluster CONTEXT | --config FILE] [--tenant TENANT] [--user USER] COMMAND [options]")
			fmt.Fprintln(out, "sfcli [account options] login --user USER --method private-key (--key NAME | --key-file PRIVATE.pem)")
			fmt.Fprintln(out, "sfcli [account options] login --user USER --method password [--credential ID] [--password-stdin] [--approval-key NAME]")
			fmt.Fprintln(out, "sfcli [account options] login --user USER --method token [--credential ID] [--token-stdin] [--approval-key NAME]")
			fmt.Fprintln(out, "--approval-key explicitly selects a registered user key in the wallet to approve the exact password/token session without widening its scopes. Private-key login uses its own registered key.")
			fmt.Fprintln(out, "sfcli [account options] enroll-admin --user-id ID --user USER (--key NAME | --key-file PRIVATE.pem) --request-id ID")
			fmt.Fprintln(out, "sfcli [account options] server-version (responding daemon metadata; no login/wallet/quorum)")
			fmt.Fprintln(out, "sfcli [account options] whoami | logout [--resume-original]")
			fmt.Fprintln(out, "Successful login credentials coexist in the encrypted wallet. With multiple saved accounts --user is required; no recent-login/default-profile fallback. --username is a login/enrollment alias and must agree with --user.")
			fmt.Fprintln(out, "Requires auth: user. Password/token use protected TTY or explicit stdin and a configured system credential backend. Wallet passwords use protected TTY or SFC_WALLET_PASSWORD_FILE (a mode 0600 file); SFC_NONINTERACTIVE=1 forbids prompts. Repeated logout queries the original pending request; --resume-original explicitly submits that unchanged intent.")
			return true
		}
	}
	return false
}

func runUser(args []string, cfg config.Client, home, peerID string, timeout time.Duration, out, diagnostic io.Writer) int {
	return runUserWithAccount(args, cfg, home, peerID, timeout, accountOptions{}, out, diagnostic)
}
func runUserWithAccount(args []string, cfg config.Client, home, peerID string, timeout time.Duration, account accountOptions, out, diagnostic io.Writer) int {
	var username, keyFile, keyName, approvalKeyName string
	var loginMethod access.Method
	var credentialID string
	var passwordStdin, tokenStdin bool
	login := args[0] == "login"
	enroll := args[0] == "enroll-admin"
	var userID, requestID string
	resumeOriginal := false
	method := ""
	if login || enroll {
		options, err := parseLoginOptions(args, account, diagnostic)
		if err != nil {
			if errors.Is(err, errLoginFlags) {
				return 2
			}
			return failure(diagnostic, err, 2)
		}
		username, keyFile, keyName = options.username, options.keyFile, options.keyName
		approvalKeyName = options.approvalKey
		userID, requestID = options.userID, options.requestID
		loginMethod, credentialID = options.method, options.credentialID
		passwordStdin, tokenStdin, account = options.passwordStdin, options.tokenStdin, options.account
	} else if args[0] == "server-version" && len(args) == 1 {
		method = "server-version"
	} else if args[0] == "whoami" && len(args) == 1 {
		method = "whoami"
	} else if args[0] == "logout" && len(args) == 1 {
		method = "logout"
	} else if args[0] == "logout" && len(args) == 2 && args[1] == "--resume-original" {
		method, resumeOriginal = "logout", true
	} else if args[0] == "service-call" {
		method = "service-call"
	} else if args[0] == "compose" {
		method = "compose"
	} else if args[0] == "manage" {
		method = "manage"
	} else {
		return failure(diagnostic, errors.New("supported user commands: login, whoami, logout, manage, compose"), 2)
	}
	// Validate command syntax and explicit scope before reading wallet input or
	// opening a transport. Defaults are values, not explicit option occurrences.
	var syntaxErr error
	switch method {
	case "manage":
		if len(args) > 1 && args[1] == "tenant-storage" {
			_, syntaxErr = parseTenantStorageOptions(args[2:], io.Discard)
		} else if len(args) > 1 && control.PublicReadMethod(args[1]) {
			_, _, _, syntaxErr = parsePublicRead(args[1:], io.Discard)
		} else if len(args) > 1 && (args[1] == "app-source" || args[1] == "app-revisions") {
			_, syntaxErr = parseAppSourceOptions(args[1], args[2:], io.Discard)
		} else if len(args) > 1 && args[1] == "tasks" {
			_, syntaxErr = parseTaskListOptions(args[2:], io.Discard)
		} else if len(args) > 1 && args[1] == "self-credentials" && len(args) != 2 {
			syntaxErr = errors.New("manage self-credentials takes no arguments")
		}
	case "service-call":
		var options serviceCallOptions
		options, syntaxErr = parseServiceCallOptions(args[1:], io.Discard)
		if syntaxErr == nil {
			_, syntaxErr = account.Target.CheckTenant(options.tenant.value, "", false)
		}
	case "compose":
		var options composeOptions
		options, syntaxErr = parseComposeDefaults(args[1:], io.Discard, account.Target)
		if syntaxErr == nil {
			_, syntaxErr = account.Target.CheckTenant(options.tenant.value, "", false)
		}
	}
	if syntaxErr != nil {
		return failure(diagnostic, syntaxErr, 2)
	}
	clusterID, _ := config.ClusterKey(cfg.Cluster)
	client := userauth.Client{Cluster: clusterID, OperationReason: account.OperationReason}
	var target sfcp.Peer
	peers := map[sfcp.Identity]sfcp.Peer{}
	for i, p := range cfg.Peers {
		key, _ := identity.ParseKey(p.Key)
		peer := sfcp.Peer{ID: p.ID, Endpoint: p.Endpoint, Policy: sfcp.Policy{Key: sfcp.Identity(key), Respond: true}}
		peers[peer.Key] = peer
		client.Peers = append(client.Peers, peer)
		if p.ID == peerID || peerID == "" && i == 0 {
			target = peer
		}
	}
	if target.ID == "" {
		return failure(diagnostic, errors.New("unknown configured peer"), 2)
	}
	if login && account.Target.ClusterName != "" {
		client.TrustIssuer = func(p sfcp.Peer) error { return trustRelayedIssuer(home, account.Target.Cluster, p, diagnostic) }
	}
	var err error
	if method == "server-version" {
		client.Self, err = identity.Ephemeral()
		if err != nil {
			return failure(diagnostic, err, 1)
		}
		defer clear(client.Self.Private)
		client.Mesh, err = sfcp.NewTransport(client.Self, clusterID, func(key sfcp.Identity) (sfcp.Peer, bool) { p, ok := peers[key]; return p, ok })
		if err != nil {
			return failure(diagnostic, err, 1)
		}
		defer client.Mesh.Close()
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		version, err := client.ServerVersion(ctx, target)
		if err != nil {
			return userFailure(diagnostic, err)
		}
		return userOutput(out, diagnostic, version)
	}
	var stored userauth.Stored

	if !enroll || keyName != "" {
		password, readErr := readWalletPassword(account.Password, account.NoInput, "Wallet password", diagnostic)
		if readErr != nil {
			return failure(diagnostic, readErr, 2)
		}
		credentials, openErr := userauth.OpenCredentials(home, password)
		clear(password)
		if openErr != nil {
			return walletFailure(diagnostic, openErr)
		}
		defer credentials.Close()
		client.Credentials, client.Username = credentials, account.User
	}
	if login || enroll {
		client.Self, err = identity.Ephemeral()
	} else {
		stored, err = userauth.Load(home, client)
		if errors.Is(err, userauth.ErrLegacyAccountUnbound) && account.User == "" {
			importCtx, cancel := context.WithTimeout(context.Background(), timeout)
			stored, err = client.Credentials.ImportLegacy(importCtx, client, target)
			cancel()
		}
		client.Self = stored.Self
		client.Username = stored.Username
	}
	if err != nil {
		return userFailure(diagnostic, err)
	}
	defer clear(client.Self.Private)
	if account.Target.Tenant != "" {
		stored.Tenant = account.Target.Tenant
		stored.TargetTenant = account.Target.Tenant
	}
	client.Mesh, err = sfcp.NewTransport(client.Self, clusterID, func(key sfcp.Identity) (sfcp.Peer, bool) { p, ok := peers[key]; return p, ok })
	if err != nil {
		return failure(diagnostic, err, 1)
	}
	defer client.Mesh.Close()
	if method == "compose" {
		options, parseErr := parseComposeDefaults(args[1:], io.Discard, account.Target)
		if parseErr == nil && composeStreaming(options) {
			ctx, stop := containerStreamContext(timeout)
			defer stop()
			return runComposeDefaults(ctx, args[1:], client, target, stored, home, account.Target, out, diagnostic)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if method == "service-call" {
		return runServiceCall(ctx, args[1:], client, target, stored, account.Target, out, diagnostic)
	}
	if method == "compose" {
		return runComposeDefaults(ctx, args[1:], client, target, stored, home, account.Target, out, diagnostic)
	}
	if method == "manage" {
		return runManagementTarget(ctx, args[1:], client, target, stored.Session, home, stored.TargetTenant, out, diagnostic)
	}
	if login || enroll {
		var key ed25519.PrivateKey
		var approvalKey ed25519.PrivateKey
		if approvalKeyName != "" {
			approvalKey, err = client.Credentials.PrivateKey(approvalKeyName)
			if err != nil {
				return failure(diagnostic, err, 1)
			}
			defer clear(approvalKey)
		}
		if enroll || loginMethod == access.PrivateKey {
			if keyName != "" {
				key, err = client.Credentials.PrivateKey(keyName)
			} else {
				key, err = identity.LoadPrivateKeyFile(keyFile)
			}
			if err != nil {
				return failure(diagnostic, err, 1)
			}
			defer clear(key)
		}
		if enroll {
			var public [32]byte
			copy(public[:], key.Public().(ed25519.PublicKey))
			intent := control.Enrollment{Schema: 1, RequestID: requestID, User: access.User{ID: userID, Username: username, Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: public, Enabled: true}}}}
			reply, err := client.Enroll(ctx, target, intent, key)
			if err != nil {
				return userFailure(diagnostic, err)
			}
			if reply.Result == nil || !reply.Found {
				return failure(diagnostic, errors.New("enrollment outcome unknown; reuse the same user/request ID"), 4)
			}
			code, status := 0, "administrator-enrolled"
			if reply.Result.Code != state.Applied {
				code, status = 3, "rejected"
			}
			if userOutput(out, diagnostic, map[string]any{"schema": 1, "status": status, "user": userID, "request": requestID, "result": reply.Result}) != 0 {
				return 1
			}
			return code
		}
		var session access.Session
		if loginMethod == access.PrivateKey {
			session, err = client.Credentials.LoginPrivate(ctx, client, target, username, key)
		} else {
			if account.NoInput && !passwordStdin && !tokenStdin {
				return failure(diagnostic, errors.New("noninteractive login requires explicit protected credential input"), 2)
			}
			secret, readErr := readLoginSecret(os.Stdin, passwordStdin || tokenStdin, diagnostic, loginMethod)
			if readErr != nil {
				return failure(diagnostic, readErr, 2)
			}
			defer clear(secret)
			if approvalKey != nil {
				session, err = client.Credentials.PasswordOrTokenApproved(ctx, client, target, username, loginMethod, credentialID, secret, approvalKey)
			} else {
				session, err = client.Credentials.PasswordOrToken(ctx, client, target, username, loginMethod, credentialID, secret)
			}
		}
		if err != nil {
			return userFailure(diagnostic, err)
		}

		return userOutput(out, diagnostic, map[string]any{"schema": 1, "status": "authenticated", "username": username, "user": session.User, "expires_at": session.ExpiresAt})
	}
	if method == "logout" {
		var op control.UserOperation
		pending := stored.Pending != nil
		if resumeOriginal && !pending {
			return failure(diagnostic, errors.New("no original pending logout to resume"), 2)
		}
		if pending {
			op = *stored.Pending
		} else {
			var nonce [16]byte
			if _, err := rand.Read(nonce[:]); err != nil {
				return failure(diagnostic, err, 1)
			}
			raw, err := control.ChangeBytes("revoke-session", stored.Session.User, stored.Session.AccountRevision, control.SessionRevocation{User: stored.Session.User, Session: stored.Session.ID})
			if err != nil {
				return failure(diagnostic, err, 1)
			}
			var change control.Change
			if err = json.Unmarshal(raw, &change); err != nil {
				return failure(diagnostic, err, 1)
			}
			op, err = client.Prepare(ctx, target, stored.Session, "logout-"+hex.EncodeToString(nonce[:]), change)
			if err != nil {
				return userFailure(diagnostic, err)
			}
			if err = userauth.StageLogout(home, client, op); err != nil {
				return failure(diagnostic, err, 1)
			}
		}
		var reply userauth.Reply
		if resumeOriginal {
			reply, err = client.Resume(ctx, target, stored.Session, op)
		} else if pending {
			reply, err = client.Result(ctx, target, stored.Session, op)
		} else {
			reply, err = client.Operation(ctx, target, op, false)
		}
		if err != nil || !reply.Found || reply.Result == nil {
			_ = userOutput(out, diagnostic, map[string]any{"schema": 1, "status": "unknown", "request": op.RequestID, "local_intent_preserved": true})
			return failure(diagnostic, errors.New("logout outcome unconfirmed; repeat logout to query the original request; no automatic resubmission"), 4)
		}
		err = userauth.SettleLogout(home, client, op, *reply.Result)
		if err != nil {
			return failure(diagnostic, err, 1)
		}
		status, code := "logged-out", 0
		newSession := pending && stored.Session.ID != op.Session.ID
		currentRetained := newSession || reply.Result.Code != state.Applied
		if newSession {
			status = "original-logout-settled"
		}
		if reply.Result.Code != state.Applied {
			status, code = "rejected", 3
		}
		if userOutput(out, diagnostic, map[string]any{"schema": 1, "status": status, "request": op.RequestID, "result": reply.Result, "current_session_retained": currentRetained}) != 0 {
			return 1
		}
		return code
	}
	if method != "whoami" {
		return failure(diagnostic, fmt.Errorf("unsupported user command %q", method), 2)
	}
	reply, err := client.Whoami(ctx, target, stored.Session)
	if err != nil {
		return userFailure(diagnostic, err)
	}
	return userOutput(out, diagnostic, map[string]any{"schema": 1, "username": stored.Username, "user": reply.User, "tenant": stored.Tenant, "expires_at": stored.Session.ExpiresAt})
}

func userOutput(out, diagnostic io.Writer, value any) int {
	if err := json.NewEncoder(out).Encode(value); err != nil {
		return failure(diagnostic, err, 1)
	}
	return 0
}

func userFailure(out io.Writer, err error) int {
	if errors.Is(err, userauth.ErrUserRequired) || errors.Is(err, userauth.ErrLoginRequired) {
		return failure(out, err, 2)
	}
	if errors.Is(err, wallet.ErrPending) {
		return failure(out, err, 4)
	}
	var remote *userauth.Error
	if errors.As(err, &remote) && remote.Code == "not-session-issuer" {
		return failure(out, errors.New("this node cannot issue user sessions: a non-voter relays only private-key logins (passwords and tokens are never relayed); log in with --method private-key, or connect explicitly to a pinned active control voter"), 3)
	}
	if errors.As(err, &remote) && remote.Code == "denied" {
		return failure(out, err, 3)
	}
	if errors.As(err, &remote) && remote.Code == "credential-write-unknown" {
		return failure(out, err, 4)
	}
	if errors.As(err, &remote) && remote.Code == "CURSOR_EXPIRED" {
		return failure(out, errors.New("CURSOR_EXPIRED: explicitly reset --since; source gaps or retained history changed"), 3)
	}
	if errors.As(err, &remote) && remote.Phase == sfcp.Unknown {
		return failure(out, err, 4)
	}
	return failure(out, err, 1)
}

// trustRelayedIssuer records the session issuer a trusted node of the
// context named when it relayed a login: this cluster's trust gains it, as
// "relayed-login", with the member address the relaying node gave.
func trustRelayedIssuer(home string, cluster [32]byte, p sfcp.Peer, diagnostic io.Writer) error {
	endpoint, err := cliprofile.ParseEndpoint("sfcp://"+p.Endpoint, true)
	if err != nil {
		return err
	}
	st, err := cliprofile.OpenStore(home, false)
	if err != nil {
		return err
	}
	defer st.Close()
	unlock, err := st.Lock()
	if err != nil {
		return err
	}
	defer unlock()
	trust, err := st.Trust(hex.EncodeToString(cluster[:]))
	if err != nil {
		return err
	}
	if trust, err = cliprofile.TrustNode(trust, cliprofile.PeerIdentity{Cluster: cluster, Key: [32]byte(p.Key), ID: p.ID, Endpoint: endpoint}, "relayed-login", time.Now()); err != nil {
		return err
	}
	if err = st.SaveTrust(trust); err != nil {
		return err
	}
	fmt.Fprintf(diagnostic, "Trusted session issuer %s (%s), named by the node that relayed this login.\n", p.ID, fingerprint(hex.EncodeToString(p.Key[:])))
	return nil
}
