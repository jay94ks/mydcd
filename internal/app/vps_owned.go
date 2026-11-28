// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"log"
	"net/netip"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/vps"
)

// Owned VPS installs (devel/design/vps-hostinger.md §3). The leader reads
// the attached instance from the vendor once, then the server enrolls from
// that address (manual), or the leader installs it over SSH (ssh), or the
// record binds the member already there (existing). The leader never buys,
// renews, powers or deletes an owned VPS here; the only vendor change is
// putting the account's SSH public key on the VM for an SSH install.

const ownedInstallTimeout = 30 * time.Minute

// ownedBusy reports whether any owned VPS still installs.
func ownedBusy(p control.Policy, s state.State) bool {
	c, err := p.OwnedVPS(s)
	if err != nil {
		return false
	}
	for _, v := range c.Servers {
		if v.Phase == control.OwnedInstalling {
			return true
		}
	}
	return false
}

func (r *Runtime) ownedVPSStep(ctx context.Context, sshTried map[string]time.Time, hostKeys map[string][]byte) error {
	local, err := r.Engine().Read(ctx, false)
	if err != nil || !ownedBusy(r.controlPolicy, local.State) {
		return err
	}
	v, err := r.currentView(ctx)
	if err != nil {
		return err
	}
	owned, err := r.controlPolicy.OwnedVPS(v.State)
	if err != nil {
		return err
	}
	accounts, err := r.controlPolicy.VPS(v.State)
	if err != nil {
		return err
	}
	members, err := r.controlPolicy.Members(v.State)
	if err != nil || !members.VoterKey(r.commandIdentity().Public) {
		return err
	}
	now := time.Now()
	for _, server := range owned.Servers {
		if server.Phase != control.OwnedInstalling {
			continue
		}
		t := ownedTarget(server)
		if server.Install != control.OwnedInstallExisting && vpsJoined(t, members) {
			return r.reportOwnedVPS(ctx, v.State, control.OwnedVPSReport{Server: server.Name, Action: control.OwnedJoined})
		}
		account, ok := accounts.Account(server.Account)
		if !ok {
			continue
		}
		if server.PublicIP == "" {
			report, err := r.checkOwnedVPS(ctx, account, members, server)
			if err != nil {
				log.Printf("owned-vps: check of %s failed: %s", server.Name, vpsLogCause(err))
				continue
			}
			return r.reportOwnedVPS(ctx, v.State, report)
		}
		if now.Sub(time.Unix(server.AttachedAt, 0)) > ownedInstallTimeout {
			return r.reportOwnedVPS(ctx, v.State, control.OwnedVPSReport{Server: server.Name, Action: control.OwnedFailedReport, Failure: "TIMEOUT"})
		}
		if server.Invitation == nil {
			if inv, ok := r.vpsInvitation(v, members, t); ok {
				return r.reportOwnedVPS(ctx, v.State, control.OwnedVPSReport{Server: server.Name, Action: control.OwnedInvited, Invitation: inv})
			}
		}
		if server.Install != control.OwnedInstallSSH {
			continue // the operator runs the install command
		}
		entry, entered := members.Entry(server.Name)
		pending := !entered || server.Invitation != nil && entry.Phase == membership.Invited
		if !pending || now.Before(sshTried[server.Name]) {
			continue
		}
		sshTried[server.Name] = now.Add(vpsSSHRetry)
		if !entered {
			// The account key must be on the VM before the first SSH.
			if err := r.attachOwnedSSHKey(ctx, account, server); err != nil {
				log.Printf("owned-vps: ssh key for %s failed: %s", server.Name, vpsLogCause(err))
				return nil
			}
		}
		if err := r.vpsSSHStep(ctx, v, account, t, entered, hostKeys); err != nil {
			log.Printf("owned-vps: ssh install of %s failed: %v", server.Name, err)
		}
		return nil
	}
	return nil
}

func (r *Runtime) ownedProvider(account control.VPSAccount) (vps.OwnedProvider, error) {
	vendor, ok := vps.LookupOwned(account.Vendor)
	if !ok {
		return nil, &vps.Error{Kind: vps.KindInvalid, Code: "OWNED_VENDOR"}
	}
	cred, err := r.vpsCredential(account)
	if err != nil {
		return nil, err
	}
	return vendor.NewOwned(cred, r.vpsEnv), nil
}

// checkOwnedVPS reads the attached instance once: it must run and have a
// public IPv4. A vendor that cannot be read now is an error (tried again
// next tick); what the vendor answered is a report.
func (r *Runtime) checkOwnedVPS(ctx context.Context, account control.VPSAccount, members membership.Directory, server control.OwnedVPS) (control.OwnedVPSReport, error) {
	report := control.OwnedVPSReport{Server: server.Name, Action: control.OwnedFailedReport}
	p, err := r.ownedProvider(account)
	if err != nil {
		return report, err
	}
	inst, err := p.Instance(ctx, server.InstanceID)
	switch {
	case vps.KindOf(err) == vps.KindNotFound:
		report.Failure = "INSTANCE_NOT_FOUND"
		return report, nil
	case err != nil:
		return report, err
	}
	report.Failure = ownedCheckFailure(inst, members, server)
	if report.Failure != "" {
		return report, nil
	}
	report.Action, report.Failure, report.PublicIP = control.OwnedChecked, "", inst.PublicIPv4
	if server.Install != control.OwnedInstallExisting {
		build, err := selfBuild()
		if err != nil {
			return report, err
		}
		report.Build = &build
	}
	return report, nil
}

// ownedCheckFailure is why an instance cannot be installed or bound ("" =
// it can).
func ownedCheckFailure(inst vps.Instance, members membership.Directory, server control.OwnedVPS) string {
	if inst.Status != vps.StatusActive {
		return "NOT_RUNNING"
	}
	ip, err := netip.ParseAddr(inst.PublicIPv4)
	if err != nil || !ip.Is4() || ip.IsPrivate() || !ip.IsGlobalUnicast() {
		return "NO_PUBLIC_IP"
	}
	if server.Install == control.OwnedInstallExisting {
		e, ok := members.Entry(server.Name)
		ap, err := netip.ParseAddrPort(e.CurrentPeer().Endpoint)
		if !ok || !membership.FullMember(e) || err != nil || ap.Addr().Unmap() != ip {
			return "IP_MISMATCH"
		}
	}
	return ""
}

func (r *Runtime) attachOwnedSSHKey(ctx context.Context, account control.VPSAccount, server control.OwnedVPS) error {
	if account.Credential.SSHPublic == "" {
		return &vps.Error{Kind: vps.KindInvalid, Code: "NO_SSH_KEY"}
	}
	p, err := r.ownedProvider(account)
	if err != nil {
		return err
	}
	return p.AttachSSHKey(ctx, server.InstanceID, account.Credential.SSHPublic)
}

func (r *Runtime) reportOwnedVPS(ctx context.Context, s state.State, report control.OwnedVPSReport) error {
	now := time.Now().Unix()
	report.Schema, report.Cluster, report.Reporter = 1, r.controlPolicy.Cluster, r.commandIdentity().Public
	report.RootRevision, report.Epoch, report.At = s.Object(control.OwnedVPSKey).Revision, s.ModuleEpoch(), uint64(now)
	report.Signature = ed25519.Sign(r.commandIdentity().Private, control.OwnedVPSReportBytes(report))
	raw, err := json.Marshal(report)
	if err != nil {
		return err
	}
	reply, err := r.appCall(ctx, "owned-vps-report", raw)
	if err != nil {
		return err
	}
	if reply.Committed == nil || reply.Committed.Result.Code != state.Applied {
		return access.ErrConflict
	}
	return nil
}
