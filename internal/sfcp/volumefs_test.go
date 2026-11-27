// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

func TestVolumeFSRoundTripCarriesDataBothWays(t *testing.T) {
	big := bytes.Repeat([]byte("v"), VolumeFSData)
	session, _ := checkerProbeWirePair(t, func(server *Transport) error {
		return server.OnVolumeFS(func(_ context.Context, s *Session, header, data []byte) ([]byte, []byte, error) {
			switch string(header) {
			case `{"op":"write"}`:
				if !bytes.Equal(data, big) {
					return nil, nil, errors.New("data lost")
				}
				return []byte(`{"n":131072}`), nil, nil
			case `{"op":"read"}`:
				return []byte(`{}`), big, nil
			case `{"op":"stat"}`:
				if data != nil {
					return nil, nil, errors.New("unexpected data")
				}
				return []byte(`{"size":1}`), nil, nil
			}
			return nil, nil, errors.New("refused")
		})
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if r, d, err := session.CallVolumeFS(ctx, []byte(`{"op":"write"}`), big); err != nil || string(r) != `{"n":131072}` || d != nil {
		t.Fatalf("write: %s %d %v", r, len(d), err)
	}
	if r, d, err := session.CallVolumeFS(ctx, []byte(`{"op":"read"}`), nil); err != nil || string(r) != `{}` || !bytes.Equal(d, big) {
		t.Fatalf("read: %s %d %v", r, len(d), err)
	}
	if r, _, err := session.CallVolumeFS(ctx, []byte(`{"op":"stat"}`), nil); err != nil || string(r) != `{"size":1}` {
		t.Fatalf("stat: %s %v", r, err)
	}
	// A refused operation ends without a reply; the caller learns it was sent.
	if _, _, err := session.CallVolumeFS(ctx, []byte(`{"op":"nope"}`), nil); err == nil || !CallSent(err) {
		t.Fatalf("refused op: %v", err)
	}
	if _, _, err := session.CallVolumeFS(ctx, []byte(`{}`), append(big, 1)); !errors.Is(err, ErrFrame) {
		t.Fatalf("oversized data: %v", err)
	}
}
