// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"math"
	"strings"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/credentials"
)

// CredentialsKey holds the builtin credential store: one sealed record per
// verifier reference under CredentialsKey/<ID>. The root holds only a count.
const CredentialsKey = "control/credentials"

// maxBuiltinCredentials bounds the store. Records that no account names are
// pruned a week after they were issued.
const maxBuiltinCredentials = 4096

// builtinCredentialRetention is how long (seconds) a record no account names
// stays, so a late activation or 'op resume' still finds it.
const builtinCredentialRetention = 7 * 86400

type credentialsRoot struct {
	Schema uint8
	Count  int
}

// CredentialStoreReport is a voter's single write to the builtin store:
// Action "put" adds Record (absent ID only), "consume" marks record ID used
// (once). The reducer checks only signed, public fields; it never opens a
// sealed record.
type CredentialStoreReport struct {
	Schema              uint8
	Cluster, Reporter   [32]byte
	RootRevision, Epoch uint64
	At                  uint64
	Action              string
	Record              *credentials.BuiltinRecord `json:",omitempty"`
	ID                  string                     `json:",omitempty"`
	Signature           []byte
}

func CredentialStoreBytes(r CredentialStoreReport) []byte {
	r.Signature = nil
	raw, _ := json.Marshal(r)
	return append([]byte("sfc-credential-store-1\x00"), raw...)
}

func (r CredentialStoreReport) Command() (state.Command, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return state.Command{}, err
	}
	cmd := state.Command{Kind: state.ModuleReport, Actor: "node/" + hex.EncodeToString(r.Reporter[:]), Epoch: r.Epoch, Key: CredentialsKey, Expected: r.RootRevision, Value: string(raw)}
	cmd.RequestID = state.ReportRequestID(cmd)
	_, err = state.EncodeCommand(cmd)
	return cmd, err
}

func builtinCredentialKey(id string) string { return CredentialsKey + "/" + id }

// BuiltinCredential reads one builtin record.
func (p Policy) BuiltinCredential(s state.State, id string) (credentials.BuiltinRecord, bool, error) {
	var r credentials.BuiltinRecord
	if len(id) != 64 || strings.Trim(id, "0123456789abcdef") != "" {
		return r, false, ErrCatalog
	}
	o := s.Object(builtinCredentialKey(id))
	if !o.Present {
		return r, false, nil
	}
	if canonical([]byte(o.Value), &r) != nil || r.ID != id || !r.Valid(p.Cluster) {
		return r, false, ErrCatalog
	}
	return r, true, nil
}

func (p Policy) credentialStoreReport(s state.State, cmd state.Command) (CredentialStoreReport, error) {
	var r CredentialStoreReport
	if cmd.Key != CredentialsKey || cmd.Kind != state.ModuleReport || canonical([]byte(cmd.Value), &r) != nil || r.Schema != 1 || r.Cluster != p.Cluster || r.Epoch != s.ModuleEpoch() || r.RootRevision != s.Object(CredentialsKey).Revision || r.At == 0 || r.At > math.MaxInt64 || !ed25519.Verify(r.Reporter[:], CredentialStoreBytes(r), r.Signature) {
		return r, ErrCatalog
	}
	switch r.Action {
	case "put":
		if r.Record == nil || r.ID != "" || !r.Record.Valid(p.Cluster) || r.Record.Sealer != r.Reporter || r.Record.Consumed {
			return r, ErrCatalog
		}
	case "consume":
		if r.Record != nil || len(r.ID) != 64 || strings.Trim(r.ID, "0123456789abcdef") != "" {
			return r, ErrCatalog
		}
	default:
		return r, ErrCatalog
	}
	want, err := r.Command()
	current, pe := p.Current(s)
	if err != nil || want != cmd || pe != nil {
		return r, ErrCatalog
	}
	// Only a voter holds the master key, so only a voter can seal or open.
	members, err := current.Members(s)
	if err != nil || !members.VoterKey(r.Reporter) {
		return r, ErrCatalog
	}
	return r, nil
}

func (p Policy) ResolveCredentialStoreReport(s state.State, caller [32]byte, raw []byte) (state.Command, error) {
	var r CredentialStoreReport
	if canonical(raw, &r) != nil || r.Reporter != caller {
		return state.Command{}, ErrCatalog
	}
	cmd, err := r.Command()
	if err == nil {
		_, err = p.credentialStoreReport(s, cmd)
	}
	return cmd, err
}

func (p Policy) reduceCredentialStore(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	r, err := p.credentialStoreReport(s, cmd)
	if err != nil {
		return nil, state.Forbidden
	}
	var root credentialsRoot
	if o := s.Object(CredentialsKey); o.Present {
		if canonical([]byte(o.Value), &root) != nil || root.Schema != 1 {
			return nil, state.Invalid
		}
	}
	root.Schema = 1
	writes := map[string][]byte{}
	if r.Action == "consume" {
		record, found, err := p.BuiltinCredential(s, r.ID)
		if err != nil {
			return nil, state.Invalid
		}
		if !found || record.Consumed {
			return nil, state.ConditionFailed
		}
		record.Consumed = true
		if writes[builtinCredentialKey(r.ID)], err = json.Marshal(record); err != nil {
			return nil, state.Invalid
		}
	} else {
		record := *r.Record
		if s.Object(builtinCredentialKey(record.ID)).Present {
			return nil, state.ConditionFailed
		}
		users, err := p.Catalog(s)
		if err != nil {
			return nil, state.Invalid
		}
		// Prune by the new record's issue time: deterministic, and no clock.
		for key, o := range s.Objects(CredentialsKey + "/") {
			if !o.Present {
				continue
			}
			var old credentials.BuiltinRecord
			if canonical([]byte(o.Value), &old) != nil || builtinCredentialKey(old.ID) != key {
				return nil, state.Invalid
			}
			if old.At+builtinCredentialRetention < record.At && !users.VerifierReferenced(old.Reference) {
				writes[key] = nil
				root.Count--
			}
		}
		if root.Count >= maxBuiltinCredentials {
			return nil, state.ConditionFailed
		}
		if writes[builtinCredentialKey(record.ID)], err = json.Marshal(record); err != nil {
			return nil, state.Invalid
		}
		root.Count++
	}
	var err2 error
	if writes[CredentialsKey], err2 = json.Marshal(root); err2 != nil {
		return nil, state.Invalid
	}
	return writes, state.Applied
}

// builtinInitialRecord checks that a builtin initial credential's sealed
// record is in the store and bound to the same public request.
func (p Policy) builtinInitialRecord(s state.State, r credentials.InitialRequest) bool {
	if r.Profile != credentials.BuiltinProfile {
		return true
	}
	record, found, err := p.BuiltinCredential(s, credentials.BuiltinID(r.Reference()))
	return err == nil && found && record.Reference == r.Reference() && record.Receipt == r.Receipt() && record.User == r.User && record.Credential == r.Credential && record.Method == r.Method && record.At == r.At && record.Sealer == r.Owner
}

// credentialsBook is the CredentialsKey book (books.go).
var credentialsBook = Book{Key: CredentialsKey, Reduce: Policy.reduceCredentialStore}
