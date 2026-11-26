// SPDX-License-Identifier: Apache-2.0

package services

import (
	"crypto/ed25519"
	"fmt"
)

// resumeJournal runs before Open's atomic save. A new kernel boot ends the
// previous process's sockets, not its durable Bridge leases or native journal.
// No old PID is looked up in the new kernel/namespace. Both boot coordinates
// were checked against each other before entering this recovery path.
func (o *DNSOwner) resumeJournal(disk dnsOwnerDisk) error {
	if disk.Boot == ([32]byte{}) || o.boot == ([32]byte{}) || o.settings.boot != disk.Boot {
		return ErrLease
	}
	uses, err := o.settings.originalDNSUses(o.dns)
	if err != nil {
		return err
	}
	if disk.Stopped && len(uses) != 0 {
		return fmt.Errorf("DNS clean pause contains unfinished queries: %w", ErrLease)
	}
	reboot := disk.Boot != o.boot
	if !disk.Stopped {
		if reboot {
			if disk.Process == nil || disk.Process.PID <= 0 || disk.Process.StartTicks == 0 || disk.Process.NamespaceInode == 0 {
				return fmt.Errorf("DNS boot recovery missing original process: %w", ErrLease)
			}
		} else if err = dnsOriginalProcessEnded(disk.Process, o.process); err != nil {
			return err
		}
		if err = o.settleExitedQueries(uses); err != nil {
			return err
		}
	}
	if reboot {
		// Pair/return with the OLD Settings boot first. Updating it before
		// originalDNSUses would orphan the original request identities.
		m, err := o.settings.ResumeBoot(o.boot)
		if err != nil {
			return err
		}
		d := o.dns
		now := o.holdClock()
		for _, view := range d.Views() {
			if !view.Retired {
				continue
			}
			d, err = d.RebaseHold(view.ID, now)
			if err != nil {
				return err
			}
		}
		o.settings, o.dns = m, d
	}
	return nil
}

// Called only during Open, after the original process's positive exit proof.
// All of that process's I/O has ended. Reuse the original paired release core
// and start the full original TTL at recovery, without inventing an answer or
// dropping Settings operations, view floors, reference or Bridge lifetimes.
func (o *DNSOwner) settleExitedQueries(uses []SettingsDNSUse) error {
	m, d := o.settings, o.dns
	now := o.holdClock()
	if !validClock(now) {
		return ErrLease
	}
	for _, use := range uses {
		proof, err := m.UseFacts(use.Runtime)
		if err != nil {
			return err
		}
		proof.Synced, proof.Stopped, proof.NoPending = true, true, true
		proof.Signature = ed25519.Sign(o.options.Key, SettingsUseCloseBytes(proof))
		m, d, err = m.ReleaseDNS(d, use, now, proof)
		if err != nil {
			return err
		}
	}
	// Open's one transaction publishes both candidates with the NEW process
	// identity. Nothing is written if any original pairing/return fails.
	o.settings, o.dns = m, d
	return nil
}
