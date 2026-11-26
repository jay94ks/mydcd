// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"

	"github.com/hashicorp/vault/api"
)

// These methods are restricted to the installed system credential provider.
// They do not accept tenant WriteRecords or open a second Vault configuration.
func (v *Vault) systemCredential(ref Reference) bool {
	return v != nil && v.profile.Prefix == "system/credentials" &&
		v.permits(ref.Profile, ref.Object) && strings.HasPrefix(ref.Object, "system/credentials/") &&
		ref.Revision == 1 && len(ref.Keys) == 1 && ref.Keys[0] == "credential"
}

func validSystemReceipt(receipt string) bool {
	raw, err := hex.DecodeString(receipt)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == receipt
}

// PutSystemCredential performs exactly one immutable CAS=0 write. The receipt
// identifies PUBLIC intent; neither a password hash nor a raw token is public.
// Any error leaves the effect unknown. ReadSystemCredential is its recovery.
func (v *Vault) PutSystemCredential(ctx context.Context, ref Reference, receipt string, material []byte) (ProviderReceipt, error) {
	if !v.systemCredential(ref) || !validSystemReceipt(receipt) || len(material) == 0 || len(material) > 32<<10 || int64(len(material))*2+1024 > v.profile.MaxBytes {
		return ProviderReceipt{}, ErrProvider
	}
	data := map[string]any{"credential": base64.StdEncoding.EncodeToString(material),
		vaultReceiptKey: vaultMetadata{Schema: 1, Receipt: receipt, Encoding: "base64"}}
	s, err := v.client.KVv2(v.profile.Mount).Put(ctx, ref.Object, data, api.WithCheckAndSet(0))
	if err != nil || s == nil || s.VersionMetadata == nil || s.VersionMetadata.Version != 1 {
		return ProviderReceipt{}, ErrProvider
	}
	return ProviderReceipt{Revision: 1, Original: receipt}, nil
}

// ReadSystemCredential only observes the original immutable write and receipt.
// Missing/denied/timed-out observations do not permit a replacement write.
func (v *Vault) ReadSystemCredential(ctx context.Context, ref Reference, receipt string) (Fetched, error) {
	if !v.systemCredential(ref) || !validSystemReceipt(receipt) {
		return Fetched{}, ErrProvider
	}
	return v.fetch(ctx, "credential", ref, receipt)
}

// ConsumeSystemCredential is an atomic, cluster-wide login claim in the same
// protected provider. CAS=0 allows at most one successful caller, including
// concurrent issuers and daemon restarts. Never delete this marker on logout.
func (v *Vault) ConsumeSystemCredential(ctx context.Context, ref Reference) error {
	if !v.systemCredential(ref) {
		return ErrProvider
	}
	digest := sha256.Sum256([]byte(ref.Profile + "/" + ref.Object + "@1"))
	data := map[string]any{"consumed": true, "reference": hex.EncodeToString(digest[:])}
	s, err := v.client.KVv2(v.profile.Mount).Put(ctx, ref.Object+"/consumed", data, api.WithCheckAndSet(0))
	if err != nil || s == nil || s.VersionMetadata == nil || s.VersionMetadata.Version != 1 {
		return ErrProvider
	}
	return nil
}
