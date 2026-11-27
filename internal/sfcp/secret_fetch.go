// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"context"
	"io"
)

// SecretFetch is a dedicated member-to-member sensitive read. There is no
// relay, datagram, early-data or management-envelope fallback. It ends like
// CertificateMaterial and VaultValue: the caller closes its write side and
// each side checks the other's EOF.
func (t *Transport) OnSecretFetch(handler func(context.Context, *Session, []byte) ([]byte, error)) error {
	return t.onSensitive(SecretFetch, handler)
}
func writeSensitiveFrame(w io.Writer, f Frame) error {
	b, err := Encode(f)
	if err != nil {
		return err
	}
	defer clear(b)
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
		b = b[n:]
	}
	return nil
}

// FetchSecret returns private response bytes owned by the caller, which must
// clear them after consuming them. Only the public request digest is echoed.
func (s *Session) FetchSecret(ctx context.Context, body []byte) ([]byte, error) {
	return s.callSensitive(ctx, SecretFetch, body)
}
