// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"log"
	"slices"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/vps"
)

// The leader drives VPS servers (devel/design/vps-nodes.md §4). Provider
// results that later servers need (the instance ID, its address, a
// failure) go to Raft as one vps-report; polling state stays in memory.

const (
	vpsTick = 15 * time.Second
	// vpsCreateTimeout bounds creating: an instance that is not running
	// with a public address by then is reported failed (it may still be
	// billed; deleting it is the user's step).
	vpsCreateTimeout = 30 * time.Minute
)

// vpsCredential opens account's sealed key pair. Only a voter holding the
// cluster master key can.
func (r *Runtime) vpsCredential(account control.VPSAccount) (vps.Credential, error) {
	master, err := r.certificateMaster()
	if err != nil {
		return vps.Credential{}, err
	}
	key, err := vps.DeriveKey(master, account.Name)
	clear(master)
	if err != nil {
		return vps.Credential{}, err
	}
	defer clear(key)
	return vps.Open(account.Credential, key)
}

func (r *Runtime) vpsLoop() {
	defer r.wg.Done()
	ticker := time.NewTicker(vpsTick)
	defer ticker.Stop()
	sshTried := map[string]time.Time{} // SSH work is paced in memory only
	hostKeys := map[string][]byte{}    // SSH host keys seen on first contact
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
		}
		if !r.Engine().IsLeader() {
			r.vpsWatcher.reset()
			continue
		}
		ctx, cancel := context.WithTimeout(r.ctx, 5*time.Minute)
		if err := r.vpsStep(ctx, sshTried, hostKeys); err != nil {
			log.Printf("vps: %s", vpsLogCause(err))
		}
		if err := r.ownedVPSStep(ctx, sshTried, hostKeys); err != nil {
			log.Printf("owned-vps: step failed: %s", vpsLogCause(err))
		}
		if local, err := r.Engine().Read(ctx, false); err == nil && ownedRunningAny(r.controlPolicy, local.State) && r.vpsWatcher.owned.due(time.Now()) {
			if err := r.ownedWatchRound(ctx, r.vpsWatcher.owned, time.Now()); err != nil {
				log.Printf("owned-vps: watch failed: %s", vpsLogCause(err))
			}
		}
		// The cost watch needs the provider only while a server runs.
		if local, err := r.Engine().Read(ctx, false); err == nil && vpsRunningAny(r.controlPolicy, local.State) && r.vpsWatcher.due(time.Now()) {
			if err := r.vpsWatchRound(ctx, r.vpsWatcher, time.Now()); err != nil {
				log.Printf("vps: watch: %s", vpsLogCause(err))
			}
		}
		if local, err := r.Engine().Read(ctx, false); err == nil && vpsRunningAny(r.controlPolicy, local.State) && r.vpsWatcher.guardDue(time.Now()) {
			if err := r.vpsGuardRound(ctx, r.vpsWatcher, time.Now()); err != nil {
				log.Printf("vps: guard: %s", vpsLogCause(err))
			}
		}
		cancel()
	}
}

func (r *Runtime) vpsStep(ctx context.Context, sshTried map[string]time.Time, hostKeys map[string][]byte) error {
	// An idle cluster costs no quorum read: the local view says whether any
	// server needs the provider at all.
	local, err := r.Engine().Read(ctx, false)
	if err != nil || !vpsBusy(r.controlPolicy, local.State) {
		return err
	}
	v, err := r.currentView(ctx)
	if err != nil {
		return err
	}
	catalog, err := r.controlPolicy.VPS(v.State)
	if err != nil {
		return err
	}
	members, err := r.controlPolicy.Members(v.State)
	if err != nil || !members.VoterKey(r.commandIdentity().Public) {
		return err
	}
	for _, server := range catalog.Servers {
		if server.Phase == control.VPSInstalling && vpsJoined(managedTarget(server), members) {
			return r.reportVPS(ctx, v.State, server.Name, vpsOutcome{Action: control.VPSRunning})
		}
		if server.Phase == control.VPSInstalling {
			if server.Invitation == nil {
				// Enrolled (ingress or SSH): sign its invitation once.
				if inv, ok := r.vpsInvitation(v, members, managedTarget(server)); ok {
					return r.reportVPS(ctx, v.State, server.Name, vpsOutcome{Action: control.VPSInvited, Invitation: inv})
				}
			}
			entry, entered := members.Entry(server.Name)
			if vpsSSHPending(server, entry, entered) && time.Now().After(sshTried[server.Name]) {
				sshTried[server.Name] = time.Now().Add(vpsSSHRetry)
				account, _ := catalog.Account(server.Account)
				if err := r.vpsSSHStep(ctx, v, account, managedTarget(server), entered, hostKeys); err != nil {
					log.Printf("vps: ssh install of %s: %v", server.Name, err)
				}
				return nil
			}
			continue
		}
		if server.Phase != control.VPSCreating && server.Phase != control.VPSDeleting && server.Phase != control.VPSStopping && server.Phase != control.VPSStarting {
			continue
		}
		if server.Phase == control.VPSStopping && time.Now().Unix() < server.StopAfter {
			continue // the DNS wait is not over
		}
		account, ok := catalog.Account(server.Account)
		if !ok {
			continue
		}
		vendor, ok := vps.LookupManaged(account.Vendor)
		if !ok {
			continue
		}
		cred, err := r.vpsCredential(account)
		if err != nil {
			return err
		}
		p := vendor.New(cred, r.vpsEnv)
		tag := server.Tag(r.controlPolicy.Cluster)
		if server.Phase == control.VPSStopping || server.Phase == control.VPSStarting {
			key := "power/" + server.Name
			outcome, sent := powerVPS(ctx, p, server, time.Now().After(sshTried[key]))
			if sent {
				sshTried[key] = time.Now().Add(vpsPowerRetry)
			}
			if outcome.Action != "" {
				return r.reportVPS(ctx, v.State, server.Name, outcome)
			}
			continue
		}
		if server.Phase == control.VPSDeleting {
			if outcome := deleteVPSInstance(ctx, p, server, tag, time.Now()); outcome.Action != "" {
				return r.reportVPS(ctx, v.State, server.Name, outcome)
			}
			continue
		}
		outcome := lookupVPSCreate(ctx, p, server, tag, time.Now())
		if outcome.Action == "" {
			continue
		}
		if outcome.Action == control.VPSInstalling {
			// The new server installs exactly this leader's sfcd.
			build, err := selfBuild()
			if err != nil {
				return err
			}
			outcome.Build = &build
		}
		if err := r.reportVPS(ctx, v.State, server.Name, outcome); err != nil {
			return err
		}
		if outcome.Action == control.VPSCreateSent {
			// Committed first, so this is the only create this server
			// ever gets, whatever happens to the reply or the leader.
			if failed := sendVPSCreate(ctx, p, server, tag); failed.Action != "" {
				after, err := r.currentView(ctx)
				if err != nil {
					return err
				}
				return r.reportVPS(ctx, after.State, server.Name, failed)
			}
		}
		return nil // the root revision moved; the next tick reads it again
	}
	return nil
}

func vpsBusy(p control.Policy, s state.State) bool {
	catalog, err := p.VPS(s)
	if err != nil {
		return false
	}
	members, err := p.Members(s)
	if err != nil {
		return false
	}
	for _, server := range catalog.Servers {
		if server.Phase == control.VPSCreating || server.Phase == control.VPSDeleting || server.Phase == control.VPSStopping || server.Phase == control.VPSStarting || server.Phase == control.VPSInstalling && vpsJoined(managedTarget(server), members) {
			return true
		}
		e, ok := members.Entry(server.Name)
		if ok && server.Phase == control.VPSInstalling && server.Invitation == nil && e.Phase == membership.Invited || vpsSSHPending(server, e, ok) {
			return true
		}
	}
	return false
}

func (r *Runtime) reportVPS(ctx context.Context, s state.State, server string, o vpsOutcome) error {
	now := time.Now().Unix()
	if o.Cap != nil {
		c := *o.Cap
		c.At, c.Month = now, vps.MonthOf(time.Unix(now, 0))
		o.Cap = &c
	}
	report := control.VPSReport{Schema: 1, Cluster: r.controlPolicy.Cluster, Reporter: r.commandIdentity().Public, Server: server, Action: o.Action,
		InstanceID: o.InstanceID, PublicIP: o.PublicIP, Failure: o.Failure, Build: o.Build, Invitation: o.Invitation, Cap: o.Cap, RootRevision: s.Object(control.VPSKey).Revision, Epoch: s.ModuleEpoch(), At: uint64(now)}
	report.Signature = ed25519.Sign(r.commandIdentity().Private, control.VPSReportBytes(report))
	raw, err := json.Marshal(report)
	if err != nil {
		return err
	}
	reply, err := r.appCall(ctx, "vps-report", raw)
	if err != nil {
		return err
	}
	if reply.Committed == nil || reply.Committed.Result.Code != state.Applied {
		return access.ErrConflict
	}
	return nil
}

// vpsOutcome is what one creating tick found. An empty Action means "look
// again on the next tick".
type vpsOutcome struct {
	Action, InstanceID, PublicIP, Failure string
	Build                                 *control.VPSBuild
	Invitation                            *membership.Invitation
	Cap                                   *control.VPSCapStop // capped: the leader fills At and Month
}

// lookupVPSCreate moves one creating server forward by reading the
// provider only. When no instance carries the tag and no create was ever
// sent, it asks for create-sent: that report is committed before the one
// and only Create (sendVPSCreate), so a slow list, a create whose reply was
// lost, or a new leader can never make a second billed instance. After it,
// an instance that does not show up is waited for until the deadline.
func lookupVPSCreate(ctx context.Context, p vps.ManagedProvider, server control.VPSServer, tag string, now time.Time) vpsOutcome {
	since := server.CreatedAt
	if server.CreateSentAt != 0 {
		since = server.CreateSentAt
	}
	late := now.Sub(time.Unix(since, 0)) > vpsCreateTimeout
	instances, err := p.Instances(ctx)
	if err != nil {
		if late && server.CreateSentAt == 0 {
			return vpsOutcome{Action: control.VPSFailed, Failure: "TIMEOUT"}
		}
		return vpsCreateError(err, "")
	}
	for _, in := range instances {
		if in.Description != tag {
			continue
		}
		switch {
		case in.Status == vps.StatusActive && in.PublicIPv4 != "":
			return vpsOutcome{Action: control.VPSInstalling, InstanceID: in.ID, PublicIP: in.PublicIPv4}
		case in.Status == vps.StatusError:
			return vpsOutcome{Action: control.VPSFailed, InstanceID: in.ID, Failure: "INSTANCE_ERROR"}
		case late:
			return vpsOutcome{Action: control.VPSFailed, InstanceID: in.ID, Failure: "TIMEOUT"}
		}
		return vpsOutcome{}
	}
	switch {
	case late:
		return vpsOutcome{Action: control.VPSFailed, Failure: "TIMEOUT"}
	case server.CreateSentAt == 0:
		return vpsOutcome{Action: control.VPSCreateSent}
	}
	return vpsOutcome{} // sent; the vendor list may still be catching up
}

// sendVPSCreate sends the single Create after create-sent is committed. A
// refusal is a failure; an unknown result is settled by lookups.
func sendVPSCreate(ctx context.Context, p vps.ManagedProvider, server control.VPSServer, tag string) vpsOutcome {
	_, err := p.Create(ctx, vps.CreateRequest{Name: server.Name, Description: tag, Zone: server.Zone, Image: server.Image, Flavor: server.Flavor, SSHKeys: server.SSHKeys, Script: server.Script})
	if err == nil {
		return vpsOutcome{}
	}
	return vpsCreateError(err, "")
}

// vpsPowerRetry paces Shutdown and Start: a vendor job takes a while and
// the next request waits for the instance to settle.
const vpsPowerRetry = 2 * time.Minute

// powerVPS moves a stopping or starting server forward. It reads the
// instance first: off (stopping) or active (starting) is the result to
// report; otherwise it asks the vendor, at most once per vpsPowerRetry
// (mayAsk), and reports sent so the caller paces the next request.
func powerVPS(ctx context.Context, p vps.ManagedProvider, server control.VPSServer, mayAsk bool) (outcome vpsOutcome, sent bool) {
	instances, err := p.Instances(ctx)
	if err != nil {
		return vpsOutcome{}, false
	}
	i := slices.IndexFunc(instances, func(in vps.Instance) bool { return in.ID == server.InstanceID })
	if i < 0 {
		log.Printf("vps: %s: instance %s is not at the provider; delete the server with 'sfcli vps delete'", server.Name, server.InstanceID)
		return vpsOutcome{}, false
	}
	stopping := server.Phase == control.VPSStopping
	switch status := instances[i].Status; {
	case stopping && status == vps.StatusOff:
		return vpsOutcome{Action: control.VPSStopped}, false
	case !stopping && status == vps.StatusActive:
		return vpsOutcome{Action: control.VPSStarted}, false
	case status == vps.StatusWorking || status == vps.StatusPending || !mayAsk:
		return vpsOutcome{}, false
	}
	if stopping {
		_ = p.Shutdown(ctx, server.InstanceID) // the next read settles it
	} else {
		_ = p.Start(ctx, server.InstanceID)
	}
	return vpsOutcome{}, true
}

// vpsJoined reports whether an installing server's invited key is a full
// member now, so the server moves to running.
func vpsJoined(server vpsTarget, members membership.Directory) bool {
	if server.Invitation == nil {
		return false
	}
	e, ok := members.Entry(server.Name)
	return ok && membership.FullMember(e) && e.JoinID == server.JoinID && e.CurrentPeer().Key == server.Invitation.Target.Key && !members.Gone(server.Name)
}

// deleteVPSInstance deletes a deleting server's instance. Once the vendor
// accepted the delete (or has no such instance) the record goes. With no
// known instance ID the instance is found by its tag; if a Create was sent
// and nothing carries the tag yet, the record stays until the create
// timeout, so a late instance is still found and deleted.
func deleteVPSInstance(ctx context.Context, p vps.ManagedProvider, server control.VPSServer, tag string, now time.Time) vpsOutcome {
	id := server.InstanceID
	if id == "" {
		if server.CreateSentAt == 0 {
			return vpsOutcome{Action: control.VPSDeleted} // no Create was ever sent
		}
		instances, err := p.Instances(ctx)
		if err != nil {
			return vpsOutcome{}
		}
		for _, in := range instances {
			if in.Description == tag {
				id = in.ID
				break
			}
		}
		if id == "" {
			if now.Sub(time.Unix(server.CreateSentAt, 0)) > vpsCreateTimeout {
				return vpsOutcome{Action: control.VPSDeleted}
			}
			return vpsOutcome{}
		}
	}
	if err := p.Delete(ctx, id); err != nil && vps.KindOf(err) != vps.KindNotFound {
		return vpsOutcome{} // tried again on the next tick
	}
	return vpsOutcome{Action: control.VPSDeleted}
}

// vpsCreateError turns a provider error into a failure, or into "try again"
// when the effect is unknown or may pass.
func vpsCreateError(err error, instance string) vpsOutcome {
	switch kind := vps.KindOf(err); kind {
	case vps.KindTransport, vps.KindProtocol, vps.KindBusy, "":
		return vpsOutcome{}
	default:
		return vpsOutcome{Action: control.VPSFailed, InstanceID: instance, Failure: string(kind)}
	}
}

func vpsLogCause(err error) string {
	if k := vps.KindOf(err); k != "" {
		return "provider " + string(k)
	}
	return "cluster read failed"
}
