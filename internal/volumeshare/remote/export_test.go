// SPDX-License-Identifier: Apache-2.0

package remote

// Abandon stops serving name as if sfcd died: the stored fds stay.
func Abandon(m *Mounts, name string) {
	// Close does this for every mount; one is enough here.
	m.mu.Lock()
	at := m.attached[name]
	delete(m.attached, name)
	m.mu.Unlock()
	if at.abandon != nil {
		at.abandon()
	}
}
