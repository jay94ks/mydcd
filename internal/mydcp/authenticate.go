// SPDX-License-Identifier: Apache-2.0

package mydcp

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
)

// authenticateStream binds the current approved TLS key to the same MYDCP
// cluster and fresh bilateral challenges on both real transport adapters.
func (t *Transport) authenticateStream(stream io.ReadWriter, key Identity, peer Peer, client bool) (*Gate, [32]byte, error) {
	var challenge [32]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		return nil, [32]byte{}, err
	}
	gate, err := NewGate(t.cluster, challenge)
	if err != nil {
		return nil, [32]byte{}, err
	}
	hello := func(ch [32]byte) Frame {
		return Frame{Purpose: Handshake, Kind: 1, Request: 1, Fields: []Field{{1, true, t.self.Public[:]}, {2, true, t.cluster[:]}, {3, true, ch[:]}}}
	}
	proof := func(ch []byte) Frame {
		var v [32]byte
		copy(v[:], ch)
		signature := ed25519.Sign(t.self.Private, ProofBytes(Identity(t.self.Public), t.cluster, v))
		return Frame{Purpose: Handshake, Kind: 2, Request: 1, Fields: []Field{{1, true, t.self.Public[:]}, {2, true, t.cluster[:]}, {3, true, ch}, {4, true, signature}}}
	}
	read := func(kind uint8) (Frame, error) {
		f, err := ReadFrame(stream, 4096)
		if err != nil {
			return f, err
		}
		if f.Purpose != Handshake || f.Kind != kind || f.Request != 1 || string(f.Fields[0].Value) != string(key[:]) || string(f.Fields[1].Value) != string(t.cluster[:]) {
			return Frame{}, ErrAdmission
		}
		return f, nil
	}
	verify := func(f Frame) error {
		b := Binding{Key: peer.Key, TLSKey: key, Cluster: t.cluster, Signature: f.Fields[3].Value}
		copy(b.Challenge[:], f.Fields[2].Value)
		return gate.Authenticate(b, true)
	}
	var peerChallenge [32]byte
	if client {
		if err = WriteFrame(stream, hello(challenge)); err != nil {
			return nil, [32]byte{}, err
		}
		other, err := read(1)
		if err != nil {
			return nil, [32]byte{}, err
		}
		copy(peerChallenge[:], other.Fields[2].Value)
		signed, err := read(2)
		if err != nil {
			return nil, [32]byte{}, err
		}
		if err = verify(signed); err != nil {
			return nil, [32]byte{}, err
		}
		if err = WriteFrame(stream, proof(other.Fields[2].Value)); err != nil {
			return nil, [32]byte{}, err
		}
		ack, err := read(1)
		if err != nil || string(ack.Fields[2].Value) != string(challenge[:]) {
			return nil, [32]byte{}, ErrAdmission
		}
	} else {
		other, err := read(1)
		if err != nil {
			return nil, [32]byte{}, err
		}
		copy(peerChallenge[:], other.Fields[2].Value)
		if err = WriteFrame(stream, hello(challenge)); err != nil {
			return nil, [32]byte{}, err
		}
		if err = WriteFrame(stream, proof(other.Fields[2].Value)); err != nil {
			return nil, [32]byte{}, err
		}
		signed, err := read(2)
		if err != nil {
			return nil, [32]byte{}, err
		}
		if err = verify(signed); err != nil {
			return nil, [32]byte{}, err
		}
		if err = WriteFrame(stream, hello([32]byte(other.Fields[2].Value))); err != nil {
			return nil, [32]byte{}, err
		}
	}
	return gate, peerChallenge, nil
}
