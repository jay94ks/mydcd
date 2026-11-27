// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	api "github.com/hashicorp/vault/api"
)

var ErrProvider = errors.New("protected provider unavailable, invalid response or unknown write")

// VaultProfile is node-local installation material. The app only names ID.
// API credentials, CA and endpoint are never inferred from the app or caller.
type VaultProfile struct {
	ID, Address, Mount, Prefix, Namespace, Token string
	Roots                                        *x509.CertPool
	Timeout                                      time.Duration
	MaxBytes                                     int64
}

func (VaultProfile) MarshalJSON() ([]byte, error) { return nil, ErrPrivateMaterial }
func (VaultProfile) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, "[redacted Vault profile]") }

type Vault struct {
	profile   VaultProfile
	client    *api.Client
	transport *http.Transport
}

func (*Vault) MarshalJSON() ([]byte, error) { return nil, ErrPrivateMaterial }
func (*Vault) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, "[redacted Vault client]") }

type limitedVaultTransport struct {
	base  http.RoundTripper
	limit int64
}

func (t limitedVaultTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if r.ContentLength > t.limit {
		r.Body.Close()
		return nil, ErrProvider
	}
	r.Body = http.MaxBytesReader(nil, r.Body, t.limit)
	return r, nil
}
func providerPath(s string) bool {
	return s != "" && !strings.ContainsAny(s, "%?#\\\x00\r\n") && !strings.HasPrefix(s, "/") && path.Clean(s) == s && s != ".." && !strings.HasPrefix(s, "../") && len(s) <= 256
}

func NewVault(p VaultProfile) (*Vault, error) {
	u, err := url.Parse(p.Address)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" || !identifier(p.ID) || !providerPath(p.Mount) || !providerPath(p.Prefix) || p.Token == "" || p.Timeout <= 0 || p.Timeout > time.Minute || p.MaxBytes < 1 || p.MaxBytes > 4<<20 {
		return nil, ErrProvider
	}
	// The SDK's constructor consults VAULT_* even with an explicit Config.
	// Reject ambient overrides before it can load a CA file, proxy or header.
	for _, v := range os.Environ() {
		key, value, _ := strings.Cut(v, "=")
		if strings.HasPrefix(key, "VAULT_") && value != "" {
			return nil, ErrProvider
		}
	}
	var roots *x509.CertPool
	if p.Roots != nil {
		roots = p.Roots.Clone()
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}, MaxIdleConns: 2, MaxIdleConnsPerHost: 2, ResponseHeaderTimeout: p.Timeout}
	httpClient := &http.Client{Transport: limitedVaultTransport{transport, p.MaxBytes}, Timeout: p.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	client, err := api.NewClient(&api.Config{Address: p.Address, HttpClient: httpClient, Timeout: p.Timeout, MaxRetries: 0, DisableRedirects: true})
	if err != nil {
		transport.CloseIdleConnections()
		return nil, ErrProvider
	}
	client.SetHeaders(http.Header{api.RequestHeaderName: []string{"true"}})
	client.SetNamespace(p.Namespace)
	client.SetToken(p.Token)
	p.Roots = roots
	return &Vault{p, client, transport}, nil
}
func (v *Vault) Close() {
	if v != nil && v.transport != nil {
		v.transport.CloseIdleConnections()
	}
}
func (v *Vault) permits(profile, object string) bool {
	return v != nil && profile == v.profile.ID && providerPath(object) && (object == v.profile.Prefix || strings.HasPrefix(object, v.profile.Prefix+"/"))
}

type vaultMetadata struct {
	Schema   uint8  `json:"schema"`
	Receipt  string `json:"receipt"`
	Encoding string `json:"encoding"`
}

const vaultReceiptKey = "_sfc_receipt"

func writeReceipt(r WriteRecord) string {
	raw, _ := json.Marshal(struct {
		Request WriteRequest
		Writer  WriteProfile
	}{r.Request, r.Writer})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Fetch reads one immutable revision; it never asks for latest or silently
// retries/falls back. Caller must first check current approval/consumer scope.
func (v *Vault) Fetch(ctx context.Context, secret string, ref Reference) (Fetched, error) {
	return v.fetch(ctx, secret, ref, "")
}
func (v *Vault) fetch(ctx context.Context, secret string, ref Reference, receipt string) (Fetched, error) {
	var err error
	ref, err = canonicalReference(ref)
	if err != nil {
		return Fetched{}, ErrProvider
	}
	if !v.permits(ref.Profile, ref.Object) || ref.Revision == 0 || ref.Revision > 1<<31-1 || len(ref.Keys) == 0 || len(ref.Keys) > 256 {
		return Fetched{}, ErrProvider
	}
	s, err := v.client.KVv2(v.profile.Mount).GetVersion(ctx, ref.Object, int(ref.Revision))
	if err != nil || s == nil || s.VersionMetadata == nil || uint64(s.VersionMetadata.Version) != ref.Revision || s.VersionMetadata.Destroyed || !s.VersionMetadata.DeletionTime.IsZero() || s.Data == nil {
		return Fetched{}, ErrProvider
	}
	managed := false
	if x, ok := s.Data[vaultReceiptKey]; ok {
		raw, _ := json.Marshal(x)
		var meta vaultMetadata
		if json.Unmarshal(raw, &meta) != nil || meta.Schema != 1 || meta.Encoding != "base64" || len(meta.Receipt) != 64 || receipt != "" && meta.Receipt != receipt {
			return Fetched{}, ErrProvider
		}
		managed = true
	}
	if receipt != "" && !managed {
		return Fetched{}, ErrProvider
	}
	count := len(s.Data)
	if managed {
		count--
	}
	if count != len(ref.Keys) {
		return Fetched{}, ErrProvider
	}
	out := Fetched{Secret: secret, Reference: ref, Values: map[string][]byte{}}
	var total int64
	for _, key := range ref.Keys {
		value, ok := s.Data[key].(string)
		if !ok || key == vaultReceiptKey {
			return Fetched{}, ErrProvider
		}
		data := []byte(value)
		if managed {
			data, err = base64.StdEncoding.DecodeString(value)
			if err != nil {
				return Fetched{}, ErrProvider
			}
		}
		total += int64(len(data))
		if total > v.profile.MaxBytes {
			return Fetched{}, ErrProvider
		}
		out.Values[key] = data
	}
	return out, nil
}

type ProviderReceipt struct {
	Revision uint64
	Original string
}

// VerifierReference is an identifier over the original PUBLIC intent receipt,
// including its write epoch. Reusing a write ID after collection cannot alias
// the previous protected record. No value/verifier hash is introduced.
func (r ProviderReceipt) VerifierReference() (string, error) {
	raw, err := hex.DecodeString(r.Original)
	if err != nil || len(raw) != 32 || hex.EncodeToString(raw) != r.Original {
		return "", ErrProvider
	}
	return "verifier-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)), nil
}

// PutOnce is one dispatched original write, with provider CAS and a receipt
// over PUBLIC intent metadata. Any I/O error remains Unknown; the caller keeps
// the original journal. No password/value digest is placed in shared receipts.
func (v *Vault) PutOnce(ctx context.Context, r WriteRecord, values map[string][]byte) (ProviderReceipt, error) {
	q := r.Request
	keys := q.Keys
	if q.Kind == VerifierWrite {
		// Verifier names are not Secret value keys. The public write intent
		// deliberately has Keys=nil; its private provider payload is fixed.
		if len(keys) != 0 {
			return ProviderReceipt{}, ErrProvider
		}
		keys = []string{"verifier"}
	}
	if !v.permits(q.Profile, q.ProviderObject) || r.Writer.ID != q.Profile || !r.Writer.Enabled || q.Kind != ValueWrite && q.Kind != VerifierWrite || r.Status() != "Dispatched" || q.ExpectedProviderRevision >= 1<<31-1 || len(values) != len(keys) || len(values) == 0 {
		return ProviderReceipt{}, fmt.Errorf("%w: write not allowed here (profile %s covers object %s: %v, writer %s enabled %v, status %s, %d of %d values)", ErrProvider, q.Profile, q.ProviderObject, v.permits(q.Profile, q.ProviderObject), r.Writer.ID, r.Writer.Enabled, r.Status(), len(values), len(keys))
	}
	if q.Kind == ValueWrite && !r.Writer.Values || q.Kind == VerifierWrite && !r.Writer.Verifiers {
		return ProviderReceipt{}, fmt.Errorf("%w: the writer profile does not take %s writes", ErrProvider, q.Kind)
	}
	data := map[string]any{}
	var total int64
	for _, key := range keys {
		value, ok := values[key]
		if !ok || key == vaultReceiptKey {
			return ProviderReceipt{}, fmt.Errorf("%w: no value for key %s", ErrProvider, key)
		}
		total += int64(len(value))
		if total > v.profile.MaxBytes/2 {
			return ProviderReceipt{}, fmt.Errorf("%w: values exceed half of the profile's max bytes", ErrProvider)
		}
		data[key] = base64.StdEncoding.EncodeToString(value)
	}
	receipt := writeReceipt(r)
	data[vaultReceiptKey] = vaultMetadata{Schema: 1, Receipt: receipt, Encoding: "base64"}
	encoded, err := json.Marshal(map[string]any{"data": data, "options": map[string]any{"cas": q.ExpectedProviderRevision}})
	if err != nil || int64(len(encoded)) > v.profile.MaxBytes {
		return ProviderReceipt{}, fmt.Errorf("%w: encoded write exceeds the profile's max bytes", ErrProvider)
	}
	s, err := v.client.KVv2(v.profile.Mount).Put(ctx, q.ProviderObject, data, api.WithCheckAndSet(int(q.ExpectedProviderRevision)))
	if err != nil {
		return ProviderReceipt{}, fmt.Errorf("%w: vault put %s/%s: %v", ErrProvider, v.profile.Mount, q.ProviderObject, err)
	}
	if s == nil || s.VersionMetadata == nil || uint64(s.VersionMetadata.Version) != q.ExpectedProviderRevision+1 {
		return ProviderReceipt{}, fmt.Errorf("%w: vault put %s/%s returned an unexpected version", ErrProvider, v.profile.Mount, q.ProviderObject)
	}
	return ProviderReceipt{uint64(s.VersionMetadata.Version), receipt}, nil
}

// ReadOriginal may prove only Applied for the original version and receipt.
// Missing, denied, overwritten metadata or transport failure never proves
// non-execution and never authorizes another provider write.
func (v *Vault) ReadOriginal(ctx context.Context, r WriteRecord) (ProviderReceipt, error) {
	q := r.Request
	if !v.permits(q.Profile, q.ProviderObject) || q.ExpectedProviderRevision >= 1<<31-1 {
		return ProviderReceipt{}, fmt.Errorf("%w: profile %s does not cover object %s", ErrProvider, q.Profile, q.ProviderObject)
	}
	s, err := v.client.KVv2(v.profile.Mount).GetVersion(ctx, q.ProviderObject, int(q.ExpectedProviderRevision+1))
	if err != nil {
		return ProviderReceipt{}, fmt.Errorf("%w: vault read %s/%s: %v", ErrProvider, v.profile.Mount, q.ProviderObject, err)
	}
	if s == nil || s.VersionMetadata == nil || uint64(s.VersionMetadata.Version) != q.ExpectedProviderRevision+1 || s.Data == nil || s.VersionMetadata.Destroyed || !s.VersionMetadata.DeletionTime.IsZero() {
		return ProviderReceipt{}, ErrProvider
	}
	raw, _ := json.Marshal(s.Data[vaultReceiptKey])
	var meta vaultMetadata
	if json.Unmarshal(raw, &meta) != nil || meta.Schema != 1 || meta.Encoding != "base64" || meta.Receipt != writeReceipt(r) {
		return ProviderReceipt{}, ErrProvider
	}
	return ProviderReceipt{uint64(s.VersionMetadata.Version), meta.Receipt}, nil
}
