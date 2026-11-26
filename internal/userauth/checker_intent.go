// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cliprofile"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/mydcp"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
)

type CheckerProvider struct {
	Node, Endpoint string
	Key            [32]byte
}

// CheckerScriptIntent freezes public content and provenance, never a private
// key. Sequence is synced before each explicitly authorized source send. Shared
// publication uses the existing OperationRecord, not another operation engine.
type CheckerScriptIntent struct {
	Compose                *CheckerComposeSource `json:",omitempty"`
	Schema                 uint8
	Profile, Cluster       [32]byte
	User, ID, Tenant, Name string
	Provider               CheckerProvider
	Descriptor             checker.SourceDescriptor
	Data                   []byte
	Expected               uint64
	Initiator              access.Session
	At                     int64
	Signature              []byte
	Sequence               uint64
	Fact                   *checker.SourceFact              `json:",omitempty"`
	ModuleProgress         map[string]CheckerModuleProgress `json:",omitempty"`
}

// CheckerComposeSource binds a staging-only child to its original compose
// preparation. Such an intent can never publish a tenant named script.
type CheckerComposeSource struct {
	Operation string
	Parent    [32]byte
}

func (CheckerScriptIntent) MarshalJSON() ([]byte, error) { return nil, ErrPrivateState }
func (CheckerScriptIntent) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[redacted lifecycle source intent]")
}

type checkerScriptIntent CheckerScriptIntent

func ValidCheckerRequestID(id string) bool {
	return len(id) > 0 && len(id) <= 256 && utf8.ValidString(id) && !strings.ContainsAny(id, "\x00\r\n")
}

func checkerUploadID(i CheckerScriptIntent) [32]byte {
	return sha256.Sum256(append([]byte("mydc-checker-upload-intent-1\x00"), i.Signature...))
}

func checkerIntentBytes(i CheckerScriptIntent) []byte {
	i.Data, i.Signature, i.Sequence, i.Fact, i.ModuleProgress = nil, nil, 0, nil, nil
	raw, _ := json.Marshal(checkerScriptIntent(i))
	return append([]byte("mydc-checker-script-intent-1\x00"), raw...)
}

func checkerProviderValid(p CheckerProvider) bool {
	if !safeID(p.Node) || p.Key == ([32]byte{}) || p.Endpoint == "" {
		return false
	}
	if strings.Contains(p.Endpoint, "://") {
		e, err := cliprofile.ParseEndpoint(p.Endpoint, false)
		return err == nil && e.URI == p.Endpoint
	}
	return config.ValidateCanonicalEndpoint(p.Endpoint) == nil
}

func validCheckerIntent(c Client, user string, i CheckerScriptIntent) bool {
	s := i.Initiator
	if i.Schema != 1 || i.Profile != c.JournalProfile() || i.Cluster != c.Cluster || i.User != user || !safeID(user) || !ValidCheckerRequestID(i.ID) || !checker.ValidScriptName(i.Name) || i.Tenant != i.Descriptor.Tenant || !checkerProviderValid(i.Provider) || i.Descriptor.Validate() != nil || uint64(len(i.Data)) != i.Descriptor.Length || !utf8.Valid(i.Data) || bytes.ContainsRune(i.Data, 0) || sha256.Sum256(i.Data) != i.Descriptor.Digest || i.Sequence > 128 {
		return false
	}
	if i.Compose != nil && (!safeID(i.Compose.Operation) || i.Compose.Parent == ([32]byte{}) || i.Expected != 0 || i.ID != composeCheckerID(i.Compose.Parent, i.Name)) {
		return false
	}
	if s.Schema != 1 || s.Cluster != c.Cluster || s.User != user || s.Key == ([32]byte{}) || s.Issuer == ([32]byte{}) || s.IssuedAt < 0 || i.At < s.IssuedAt || i.At >= s.ExpiresAt || s.ExpiresAt-s.IssuedAt > access.MaxSessionSeconds || !ed25519.Verify(s.Issuer[:], access.SessionBytes(s), s.Signature) || !ed25519.Verify(s.Key[:], checkerIntentBytes(i), i.Signature) {
		return false
	}
	if !validCheckerModules(i) {
		return false
	}
	if i.Fact != nil {
		upload := checkerUploadID(i)
		if i.Fact.Upload == nil || *i.Fact.Upload != upload {
			return false
		}
	}
	return i.Fact == nil || i.Sequence > 0 && i.Fact.Verify() == nil && i.Fact.Cluster == c.Cluster && i.Fact.Tenant == i.Tenant && i.Fact.Owner == i.Provider.Key && i.Fact.ContentDigest() == i.Descriptor.ContentDigest()
}

func checkerIntentRoot(home string, c Client, user string, create bool) (*os.Root, error) {
	r, err := operationRoot(home, c, user, create)
	if err != nil {
		return nil, err
	}
	if !create {
		if _, err := r.Lstat("checker-scripts"); os.IsNotExist(err) {
			r.Close()
			return nil, ErrOperationMissing
		}
	}
	next, err := descend(r, "checker-scripts", create)
	r.Close()
	return next, err
}

func readCheckerIntent(root *os.Root, c Client, user, id string) (CheckerScriptIntent, error) {
	var i checkerScriptIntent
	if _, err := root.Lstat(operationName(id)); os.IsNotExist(err) {
		return CheckerScriptIntent{}, ErrOperationMissing
	}
	if readPrivateLimit(root, operationName(id), &i, 512<<10) != nil || !validCheckerIntent(c, user, CheckerScriptIntent(i)) || i.ID != id {
		return CheckerScriptIntent{}, ErrPrivateState
	}
	return CheckerScriptIntent(i), nil
}

func LoadCheckerScript(home string, c Client, current access.Session, id string) (CheckerScriptIntent, error) {
	if c.Verify(current) != nil || !ValidCheckerRequestID(id) {
		return CheckerScriptIntent{}, ErrPrivateState
	}
	r, err := checkerIntentRoot(home, c, current.User, false)
	if err != nil {
		return CheckerScriptIntent{}, err
	}
	defer r.Close()
	return readCheckerIntent(r, c, current.User, id)
}

// CheckerProviderPeer keeps the original node/key identity and uses only its
// CURRENT trusted location. The original endpoint remains provenance; changing
// a trusted address does not require rewriting an intent or reapproving a key.
func CheckerProviderPeer(c Client, p CheckerProvider) (mydcp.Peer, error) {
	if !checkerProviderValid(p) {
		return mydcp.Peer{}, ErrPrivateState
	}
	for _, peer := range c.Peers {
		if peer.ID == p.Node && [32]byte(peer.Key) == p.Key {
			current := CheckerProvider{Node: peer.ID, Endpoint: peer.Endpoint, Key: [32]byte(peer.Key)}
			if checkerProviderValid(current) {
				return peer, nil
			}
		}
	}
	return mydcp.Peer{}, ErrPrivateState
}

func StageCheckerScript(home string, c Client, current access.Session, id, name string, provider mydcp.Peer, d checker.SourceDescriptor, data []byte, expected uint64) (CheckerScriptIntent, error) {
	return stageCheckerScript(home, c, current, id, name, provider, d, data, expected, nil)
}

func stageCheckerScript(home string, c Client, current access.Session, id, name string, provider mydcp.Peer, d checker.SourceDescriptor, data []byte, expected uint64, compose *CheckerComposeSource) (CheckerScriptIntent, error) {
	if c.Verify(current) != nil || c.Self == nil || d.Validate() != nil || uint64(len(data)) != d.Length {
		return CheckerScriptIntent{}, ErrPrivateState
	}
	if compose != nil {
		copy := *compose
		compose = &copy
	}
	i := CheckerScriptIntent{Compose: compose, Schema: 1, Profile: c.JournalProfile(), Cluster: c.Cluster, User: current.User, ID: id, Tenant: d.Tenant, Name: name, Provider: CheckerProvider{Node: provider.ID, Endpoint: provider.Endpoint, Key: [32]byte(provider.Key)}, Descriptor: d.Clone(), Data: bytes.Clone(data), Expected: expected, Initiator: current, At: time.Now().Unix()}
	if _, err := CheckerProviderPeer(c, i.Provider); err != nil {
		return CheckerScriptIntent{}, err
	}
	i.Signature = ed25519.Sign(c.Self.Private, checkerIntentBytes(i))
	if !validCheckerIntent(c, current.User, i) {
		return CheckerScriptIntent{}, ErrPrivateState
	}
	r, err := checkerIntentRoot(home, c, current.User, true)
	if err != nil {
		return CheckerScriptIntent{}, err
	}
	defer r.Close()
	unlock, err := lockProfile(r)
	if err != nil {
		return CheckerScriptIntent{}, err
	}
	defer unlock()
	old, err := readCheckerIntent(r, c, current.User, id)
	if err == nil {
		if !bytes.Equal(checkerIntentBytes(old), checkerIntentBytes(i)) || !bytes.Equal(old.Signature, i.Signature) || !bytes.Equal(old.Data, i.Data) {
			return CheckerScriptIntent{}, ErrPrivateState
		}
		return old, nil
	}
	if err != ErrOperationMissing {
		return CheckerScriptIntent{}, err
	}
	dir, err := r.Open(".")
	if err != nil {
		return CheckerScriptIntent{}, err
	}
	names, err := dir.Readdirnames(operationLimit + 2)
	dir.Close()
	if err != nil && err != io.EOF || len(names) > operationLimit {
		return CheckerScriptIntent{}, ErrPrivateState
	}
	if err := writePrivateLimit(r, operationName(id), checkerScriptIntent(i), 512<<10); err != nil {
		return CheckerScriptIntent{}, err
	}
	return i, nil
}

// ReplaceCheckerScript is a private-file CAS on only the send sequence/fact.
// Source/pins/initial signature/CAS cannot change through recovery or relogin.
func ReplaceCheckerScript(home string, c Client, current access.Session, old, next CheckerScriptIntent) error {
	if !samePublic(old.ModuleProgress, next.ModuleProgress) || c.Verify(current) != nil || !validCheckerIntent(c, current.User, old) || !validCheckerIntent(c, current.User, next) || !bytes.Equal(checkerIntentBytes(old), checkerIntentBytes(next)) || !bytes.Equal(old.Signature, next.Signature) || !bytes.Equal(old.Data, next.Data) || next.Sequence < old.Sequence || next.Sequence > old.Sequence+1 || old.Fact != nil && (!samePublic(old.Fact, next.Fact) || next.Sequence != old.Sequence) || next.Sequence != old.Sequence && next.Fact != nil {
		return ErrPrivateState
	}
	return replaceCheckerIntent(home, c, current, old, next)
}

func replaceCheckerIntent(home string, c Client, current access.Session, old, next CheckerScriptIntent) error {
	r, err := checkerIntentRoot(home, c, current.User, false)
	if err != nil {
		return err
	}
	defer r.Close()
	unlock, err := lockProfile(r)
	if err != nil {
		return err
	}
	defer unlock()
	actual, err := readCheckerIntent(r, c, current.User, old.ID)
	if err != nil || !samePublic(checkerScriptIntent(actual), checkerScriptIntent(old)) {
		return ErrPrivateState
	}
	return writePrivateLimit(r, operationName(next.ID), checkerScriptIntent(next), 512<<10)
}

func CheckerRegistrationMatches(i CheckerScriptIntent, op control.UserOperation) bool {
	if i.Compose != nil || i.Fact == nil || op.Change.Action != "put-lifecycle-script" || op.Change.Principal != i.User || op.Session.User != i.User || op.RequestID != i.ID || op.Change.Expected != i.Expected || control.UploadCASAllowed(op.Change.Action) || control.AppDownCASAllowed(op.Change) {
		return false
	}
	want, _ := json.Marshal(control.LifecycleScriptPut{Tenant: i.Tenant, Name: i.Name, Source: *i.Fact})
	return bytes.Equal(op.Change.Payload, want) && op.VerifyOriginal(i.Cluster) == nil
}

// PrepareCheckerRegistration creates the FIRST management signature only after
// staging/recovery produced a fact. The existing Prepare captures root/epoch
// at this first signature; later recovery loads the immutable OperationRecord.
func PrepareCheckerRegistration(ctx context.Context, c Client, target mydcp.Peer, current access.Session, i CheckerScriptIntent) (control.UserOperation, error) {
	if i.Compose != nil || c.Verify(current) != nil || !validCheckerIntent(c, current.User, i) || i.Fact == nil || c.Self == nil {
		return control.UserOperation{}, ErrPrivateState
	}
	payload, err := json.Marshal(control.LifecycleScriptPut{Tenant: i.Tenant, Name: i.Name, Source: *i.Fact})
	if err != nil {
		return control.UserOperation{}, err
	}
	op, err := c.Prepare(ctx, target, current, i.ID, control.Change{Schema: 1, Action: "put-lifecycle-script", Principal: current.User, Expected: i.Expected, Payload: payload})
	if err != nil {
		return control.UserOperation{}, err
	}
	if !CheckerRegistrationMatches(i, op) {
		return control.UserOperation{}, ErrPrivateState
	}
	return op, nil
}
