// SPDX-License-Identifier: Apache-2.0

package sfcp

import "context"

// VaultValue is exclusively voter-to-voter traffic of builtin Secret values:
// a writing voter replicating a sealed value, or a voter or consumer asking
// a holder for one. Bodies carry sealed bytes only, never plain values; the
// handler checks that both ends are current voters where it must.
func (t *Transport) OnVaultValue(handler func(context.Context, *Session, []byte) ([]byte, error)) error {
	return t.onSensitive(VaultValue, handler)
}
func (s *Session) CallVaultValue(ctx context.Context, body []byte) ([]byte, error) {
	return s.callSensitive(ctx, VaultValue, body)
}
