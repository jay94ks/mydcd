// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/secrets"
	"github.com/jay94ks/mydcd/internal/userauth"
	"golang.org/x/sys/unix"
)

type groupPasswordFDs struct{ values map[string]int }

func (g *groupPasswordFDs) String() string { return "explicit protected Group descriptors" }
func (g *groupPasswordFDs) Set(value string) error {
	name, number, ok := strings.Cut(value, "=")
	realm, group, qualified := strings.Cut(name, "/")
	fd, err := strconv.Atoi(number)
	if !ok || !qualified || realm != "" && !lifecycle.ValidID(realm) || !lifecycle.ValidID(group) || err != nil || fd < 3 || fd > 1<<20 || len(g.values) >= 4096 {
		return errors.New("Group password FD requires REALM/GROUP=FD >=3 (cluster: /GROUP)")
	}
	if g.values == nil {
		g.values = map[string]int{}
	}
	if _, exists := g.values[name]; exists {
		return errors.New("duplicate Group password descriptor")
	}
	for _, old := range g.values {
		if old == fd {
			return errors.New("each Group requires its own explicit descriptor")
		}
	}
	g.values[name] = fd
	return nil
}

type composeApprovalFailure struct {
	code  int
	cause error
}

func (e *composeApprovalFailure) Error() string { return e.cause.Error() }
func (e *composeApprovalFailure) Unwrap() error { return e.cause }
func approvalFailure(code int, err error) error { return &composeApprovalFailure{code, err} }

func readGroupPassword(o composeOptions, target secrets.Target, diagnostic io.Writer) ([]byte, error) {
	name := target.Realm + "/" + target.Group
	if fd, ok := o.passwordFDs.values[name]; ok {
		dup, err := unix.Dup(fd)
		if err != nil {
			return nil, identity.ErrCredential
		}
		input := os.NewFile(uintptr(dup), "Group-password")
		defer input.Close()
		value, err := io.ReadAll(io.LimitReader(input, 1026))
		if err != nil {
			clear(value)
			return nil, identity.ErrCredential
		}
		secret := bytes.TrimSuffix(value, []byte{'\n'})
		if len(secret) == 0 || len(secret) > 1024 || bytes.ContainsAny(secret, "\r\n\x00") {
			clear(value)
			return nil, identity.ErrCredential
		}
		return secret, nil
	}
	if o.noInput {
		return nil, fmt.Errorf("Secret Group %s requires an existing approval or explicit --group-password-fd", name)
	}
	tty, err := openPromptTerminal()
	if err != nil {
		return nil, fmt.Errorf("Secret Group %s needs a hidden terminal or explicit --group-password-fd", name)
	}
	defer tty.Close()
	_, _ = fmt.Fprintf(diagnostic, "Secret Group %s: namespace %s for %s/%s (%d services, %d nodes)\nPassword: ", name, strings.Join(target.Actions[:], "+"), target.App, target.Deployment, len(target.Services), len(target.Nodes))
	secret, err := identity.ReadPassword(int(tty.Fd()))
	_, _ = fmt.Fprintln(diagnostic)
	return secret, err
}

func ensureComposeApprovals(ctx context.Context, o composeOptions, intent userauth.ComposeIntent, origin control.UserOperation, tenant, home string, c userauth.Client, target mydcp.Peer, stored userauth.Stored, diagnostic io.Writer) error {
	if intent.Move != nil && intent.Move.App != nil && intent.Move.App.CD != nil {
		// The move signer may be a different authorized administrator. Group
		// consent remains with the registered requester: cd approve --operation.
		return nil
	}
	b, err := deployment.DecodeBlueprint(intent.Artifact)
	if err != nil {
		return err
	}
	uses, err := b.ApprovalUses(origin.Session.Key)
	if err != nil {
		return err
	}
	var realms []string
	for realm := range uses {
		realms = append(realms, realm)
	}
	slices.Sort(realms)
	return ensureAppApprovalRealms(ctx, o, intent.ID, origin, tenant, home, c, target, stored, diagnostic, realms, nil)
}

func ensureAppApprovalRealms(ctx context.Context, o composeOptions, id string, origin control.UserOperation, tenant, home string, c userauth.Client, target mydcp.Peer, stored userauth.Stored, diagnostic io.Writer, realms []string, selection *control.AppApprovalSelection) error {
	var required []control.VaultApprovalTarget
	for _, realm := range realms {
		plan, err := c.PlanVaultApprovals(ctx, target, stored.Session, tenant, control.VaultApprovalPlanRequest{Realm: realm, ID: "compose/" + id, Origin: &origin, Selection: selection})
		if err != nil {
			return approvalFailure(3, fmt.Errorf("planning the Group approvals of %s: %w (does every secret it names exist there?)", realmName(realm), err))
		}
		required = append(required, plan.Targets...)
	}
	for name := range o.passwordFDs.values {
		if !slices.ContainsFunc(required, func(v control.VaultApprovalTarget) bool { return v.Target.Realm+"/"+v.Target.Group == name }) {
			return approvalFailure(2, fmt.Errorf("descriptor for an unrequired Group %s", name))
		}
	}
	if len(required) > 0 {
		if err := userauth.PrepareComposeApprovals(home, c, stored.Session, id); err != nil {
			return err
		}
	}
	for _, v := range required {
		if v.Approver == nil {
			return approvalFailure(3, errors.New("Group plan lacks a current approver"))
		}
		attempt, loadErr := userauth.LoadComposeApproval(home, c, stored.Session, id, origin, v.Target, *v.Approver, selection)
		if loadErr != nil && !errors.Is(loadErr, userauth.ErrOperationMissing) {
			return approvalFailure(4, loadErr)
		}
		if v.Existing != nil {
			if loadErr == nil && attempt.Outcome == "pending" {
				if err := userauth.RecordComposeApproval(home, c, stored.Session, attempt, "confirmed"); err != nil {
					return err
				}
			}
			continue
		}
		key, err := identity.ParseKey(v.Approver.Key)
		if err != nil {
			return approvalFailure(3, err)
		}
		peer := mydcp.Peer{ID: v.Approver.ID, Endpoint: v.Approver.Endpoint, Policy: mydcp.Policy{Key: mydcp.Identity(key), Respond: true}}
		approved := map[mydcp.Identity]mydcp.Peer{peer.Key: peer}
		for _, pin := range c.Peers {
			approved[pin.Key] = pin
		}
		// The new server pin comes from the authenticated quorum scope plan; it
		// is response-only and does not change the saved profile/node authority.
		approved[peer.Key] = peer
		remote := c
		remote.Mesh, err = mydcp.NewTransport(c.Self, c.Cluster, func(k mydcp.Identity) (mydcp.Peer, bool) { p, ok := approved[k]; return p, ok })
		if err != nil {
			return err
		}
		err = func() error {
			defer remote.Mesh.Close()
			if loadErr == nil && attempt.Outcome == "pending" {
				if o.method != "resume" {
					return approvalFailure(4, userauth.ErrApprovalUnknown)
				}
				_, err := remote.WriteVault(ctx, peer, stored.Session, userauth.SecretRequest{Realm: v.Target.Realm, ID: v.Target.ApprovalID, Mode: "approve", Target: &v.Target, Origin: &origin, Selection: selection})
				if err != nil {
					return approvalFailure(4, userauth.ErrApprovalUnknown)
				}
				return userauth.RecordComposeApproval(home, c, stored.Session, attempt, "confirmed")
			}
			if loadErr == nil && attempt.Outcome == "confirmed" {
				return approvalFailure(3, errors.New("original Group approval is no longer valid; preserve its original identity"))
			}
			secret, err := readGroupPassword(o, v.Target, diagnostic)
			if err != nil {
				return approvalFailure(2, err)
			}
			defer clear(secret)
			if ctx.Err() != nil {
				return approvalFailure(4, ctx.Err())
			}
			attempt.Outcome = "pending"
			if err := userauth.StageComposeApproval(home, c, stored.Session, attempt); err != nil {
				return err
			}
			_, err = remote.WriteVault(ctx, peer, stored.Session, userauth.SecretRequest{Realm: v.Target.Realm, ID: v.Target.ApprovalID, Mode: "approve", Target: &v.Target, Password: secret, Origin: &origin, Selection: selection})
			if err != nil {
				var denied *userauth.Error
				if errors.As(err, &denied) && denied.Phase == mydcp.Completed && denied.Code == "denied" {
					if e := userauth.RecordComposeApproval(home, c, stored.Session, attempt, "rejected"); e != nil {
						return e
					}
					return approvalFailure(3, err)
				}
				if errors.As(err, &denied) && denied.Phase == mydcp.NotSent {
					if e := userauth.RecordComposeApproval(home, c, stored.Session, attempt, "not-sent"); e != nil {
						return e
					}
				}
				return approvalFailure(4, userauth.ErrApprovalUnknown)
			}
			return userauth.RecordComposeApproval(home, c, stored.Session, attempt, "confirmed")
		}()
		if err != nil {
			return err
		}
	}
	return nil
}
