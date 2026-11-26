// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"context"
	"encoding/hex"
	"slices"
)

// VerifierBinding retains only a fixed protected provider reference and a
// receipt over PUBLIC original intent. It contains no verifier/value digest.
// It lives with the Group across original write-history collection.
type VerifierBinding struct {
	Reference Reference
	Receipt   string
}

func validVerifierBinding(realm string, o Object) bool {
	if o.VerifierBinding == nil {
		return false
	}
	v := o.VerifierBinding
	canonical, err := canonicalReference(v.Reference)
	receipt, decodeErr := hex.DecodeString(v.Receipt)
	return err == nil && canonical.Profile == v.Reference.Profile && canonical.Object == verifierObject(realm, o.ID, o.Generation) && slices.Equal(v.Reference.Keys, []string{"verifier"}) && decodeErr == nil && len(receipt) == 32 && hex.EncodeToString(receipt) == v.Receipt
}
func (t Tree) Verifier(id string) (VerifierBinding, error) {
	o, ok := t.objects[id]
	if !ok || o.Kind != Group || !o.Protected || o.Status != Active || !validVerifierBinding(t.tenant, o) {
		return VerifierBinding{}, ErrPolicy
	}
	v := *o.VerifierBinding
	v.Reference.Keys = slices.Clone(v.Reference.Keys)
	return v, nil
}

// FetchVerifier checks the exact immutable version AND the public original
// receipt, so a current Group cannot silently use another stored record.
func (v *Vault) FetchVerifier(ctx context.Context, id string, b VerifierBinding) (Fetched, error) {
	if len(b.Receipt) != 64 || !slices.Equal(b.Reference.Keys, []string{"verifier"}) {
		return Fetched{}, ErrProvider
	}
	return v.fetch(ctx, id, b.Reference, b.Receipt)
}
func (b VerifierBinding) Equal(other VerifierBinding) bool {
	return b.Receipt == other.Receipt && b.Reference.Profile == other.Reference.Profile && b.Reference.Object == other.Reference.Object && b.Reference.Revision == other.Reference.Revision && slices.Equal(b.Reference.Keys, other.Reference.Keys)
}
