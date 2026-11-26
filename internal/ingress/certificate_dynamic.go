// SPDX-License-Identifier: Apache-2.0

package ingress

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// CertificateVersion is a node-private adapter result. Never serialize this
// type into a journal, observation or shared management result.
type CertificateVersion struct {
	Digest [32]byte
	// Fingerprint is the store certificate ID (leaf DER SHA-256).
	Fingerprint [32]byte
	NotAfter    int64
	Certificate tls.Certificate
}

func (CertificateVersion) MarshalJSON() ([]byte, error) {
	return nil, errors.New("private ingress certificate material")
}
func (CertificateVersion) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[private ingress certificate]")
}

// ErrCertificateWithdrawn means a current authoritative snapshot has no
// permitted selection. It fences cached keys; transport/load failure does not.
var ErrCertificateWithdrawn = errors.New("certificate selection withdrawn")

// CertificateSource returns the store certificates linked to one SNI host
// (every key algorithm), reusing previous pairs whose material is unchanged.
type CertificateSource func(ctx context.Context, host string, previous []CertificateVersion) ([]CertificateVersion, error)
type CertificateObservation struct {
	Host string
	// Fingerprint is the store certificate ID.
	Fingerprint [32]byte
	// Family is the key family of the loaded pair: ecdsa or rsa.
	Family   string `json:",omitempty"`
	NotAfter int64
	LoadedAt int64
	Error    string `json:",omitempty"`
}
type certificateState struct {
	pairs     []CertificateVersion
	loadedAt  int64
	lastError string
	checkedAt int64
	public    []CertificateObservation
}

func (m *Manager) SetCertificateSource(source CertificateSource) {
	m.certMu.Lock()
	defer m.certMu.Unlock()
	m.certificateSource = source
	for key, state := range m.certificateCache {
		state.checkedAt = 0
		m.certificateCache[key] = state
	}
}
func (m *Manager) expireCertificateCache() {
	m.certMu.Lock()
	defer m.certMu.Unlock()
	now := time.Now().Unix()
	for key, state := range m.certificateCache {
		valid := state.pairs[:0]
		for _, pair := range state.pairs {
			if now < pair.NotAfter {
				valid = append(valid, pair)
			}
		}
		clear(state.pairs[len(valid):])
		state.pairs = valid
		m.certificateCache[key] = state
	}
}
func (m *Manager) cachedCertificateVersions(key string) ([]CertificateVersion, bool) {
	m.certMu.Lock()
	defer m.certMu.Unlock()
	prior := m.certificateCache[key]
	now := time.Now()
	if prior.checkedAt == 0 || now.UnixMilli() < prior.checkedAt || now.UnixMilli()-prior.checkedAt >= 1000 {
		return nil, false
	}
	for _, pair := range prior.pairs {
		if now.Unix() >= pair.NotAfter {
			return nil, false
		}
	}
	return append([]CertificateVersion(nil), prior.pairs...), true
}
func (m *Manager) certificateVersions(ctx context.Context, name string) ([]CertificateVersion, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if name == "" {
		return nil, errors.New("certificate missing: no server name")
	}
	key := name
	if pairs, hit := m.cachedCertificateVersions(key); hit {
		if len(pairs) == 0 {
			return nil, errors.New("certificate missing or expired")
		}
		return pairs, nil
	}
	m.certLoadMu.Lock()
	defer m.certLoadMu.Unlock()
	if pairs, hit := m.cachedCertificateVersions(key); hit {
		if len(pairs) == 0 {
			return nil, errors.New("certificate missing or expired")
		}
		return pairs, nil
	}
	m.certMu.Lock()
	source := m.certificateSource
	previous := append([]CertificateVersion(nil), m.certificateCache[key].pairs...)
	m.certMu.Unlock()
	var pairs []CertificateVersion
	var err error
	if source == nil {
		err = ErrRoute
	} else {
		pairs, err = source(ctx, name, previous)
	}
	now := time.Now()
	if err == nil {
		if len(pairs) == 0 {
			err = ErrRoute
		}
		for at := range pairs {
			p := &pairs[at]
			if len(p.Certificate.Certificate) == 0 || p.Certificate.PrivateKey == nil {
				err = ErrRoute
				break
			}
			leaf, e := x509.ParseCertificate(p.Certificate.Certificate[0])
			if e != nil || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
				err = ErrRoute
				break
			}
			if !strings.HasPrefix(name, "*.") && leaf.VerifyHostname(name) != nil {
				err = ErrRoute
				break
			}
			if sha256.Sum256(leaf.Raw) != p.Fingerprint || p.NotAfter != leaf.NotAfter.Unix() {
				err = ErrRoute
				break
			}
			signer, ok := p.Certificate.PrivateKey.(crypto.Signer)
			if !ok {
				err = ErrRoute
				break
			}
			public, e := x509.MarshalPKIXPublicKey(signer.Public())
			if e != nil || !bytes.Equal(public, leaf.RawSubjectPublicKeyInfo) {
				err = ErrRoute
				break
			}
			p.Certificate.Leaf = leaf
		}
	}
	m.certMu.Lock()
	defer m.certMu.Unlock()
	if m.certificateCache == nil {
		m.certificateCache = map[string]certificateState{}
	}
	if _, exists := m.certificateCache[key]; !exists && len(m.certificateCache) >= 1024 {
		oldest := ""
		var checked int64
		for candidate, state := range m.certificateCache {
			if oldest == "" || state.checkedAt < checked || state.checkedAt == checked && candidate < oldest {
				oldest, checked = candidate, state.checkedAt
			}
		}
		delete(m.certificateCache, oldest)
	}
	state := m.certificateCache[key]
	if err == nil {
		state = certificateState{pairs: pairs, loadedAt: now.UnixMilli()}
		for _, p := range pairs {
			state.public = append(state.public, CertificateObservation{Host: name, Fingerprint: p.Fingerprint, Family: keyFamily(p.Certificate.Leaf), NotAfter: p.NotAfter, LoadedAt: state.loadedAt})
		}
	} else if errors.Is(err, ErrCertificateWithdrawn) {
		clear(state.pairs)
		state.pairs = nil
		state.lastError = "certificate-withdrawn"
	} else {
		state.lastError = "certificate-load-failed"
	}
	state.checkedAt = now.UnixMilli()
	valid := []CertificateVersion{}
	for _, pair := range state.pairs {
		if now.Unix() < pair.NotAfter {
			valid = append(valid, pair)
		}
	}
	state.pairs = valid // expired keys/chains leave the cache; public metadata remains
	m.certificateCache[key] = state
	if len(valid) == 0 {
		return nil, errors.New("certificate missing or expired")
	}
	return append([]CertificateVersion(nil), valid...), nil
}

func keyFamily(leaf *x509.Certificate) string {
	if leaf == nil {
		return ""
	}
	if _, ok := leaf.PublicKey.(*ecdsa.PublicKey); ok {
		return "ecdsa"
	}
	return "rsa"
}

// dynamicCertificateConfig selects by SNI host only. admit, when set,
// refuses a host before any certificate is loaded.
func (m *Manager) dynamicCertificateConfig(admit func(string) error) *tls.Config {
	return &tls.Config{SessionTicketsDisabled: true, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}, GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		name := strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))
		if admit != nil {
			if err := admit(name); err != nil {
				return nil, err
			}
		}
		pairs, err := m.certificateVersions(hello.Context(), name)
		if err != nil {
			return nil, err
		}
		sort.SliceStable(pairs, func(i, j int) bool {
			_, a := pairs[i].Certificate.Leaf.PublicKey.(*ecdsa.PublicKey)
			_, b := pairs[j].Certificate.Leaf.PublicKey.(*ecdsa.PublicKey)
			return a && !b
		})
		for at := range pairs {
			if hello.SupportsCertificate(&pairs[at].Certificate) == nil {
				return &pairs[at].Certificate, nil
			}
		}
		return nil, errors.New("no supported ingress certificate")
	}}
}
func (m *Manager) certificateObservations(s Spec) []CertificateObservation {
	m.expireCertificateCache()
	// Gateway state is read before certMu; the two locks are never nested.
	tlsRoutes := []Route{}
	for _, r := range s.Routes {
		if m.routeServesTLS(s, r) {
			tlsRoutes = append(tlsRoutes, r)
		}
	}
	m.certMu.Lock()
	defer m.certMu.Unlock()
	out := []CertificateObservation{}
	for key, state := range m.certificateCache {
		name := key
		used := false
		for _, r := range tlsRoutes {
			used = used || (r.Host == name || strings.HasPrefix(r.Host, "*.") && strings.HasSuffix(name, r.Host[1:]))
		}
		if !used {
			continue
		}
		if len(state.public) == 0 {
			out = append(out, CertificateObservation{Host: name, Error: "missing"})
			continue
		}
		for _, public := range state.public {
			observation := public
			observation.Error = state.lastError
			if time.Now().Unix() >= public.NotAfter {
				observation.Error = "expired"
			}
			out = append(out, observation)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		if out[i].Family != out[j].Family {
			return out[i].Family < out[j].Family // ecdsa before rsa
		}
		return bytes.Compare(out[i].Fingerprint[:], out[j].Fingerprint[:]) < 0
	})
	return out
}

// Plain HTTP shared listeners do not consume certificates and must not emit
// missing-certificate events just because their app uses a shared socket.
func (m *Manager) routeServesTLS(s Spec, route Route) bool {
	for _, listener := range s.Listeners {
		if listener.Shared != "" {
			m.gatewayMu.Lock()
			g := m.gateways[listener.Shared]
			enabled := g != nil && g.definition.TLS && gatewayIncludes(route.Gateway, g.kind)
			m.gatewayMu.Unlock()
			if enabled {
				return true
			}
			continue
		}
		if listener.TLS {
			return true
		}
	}
	return false
}
