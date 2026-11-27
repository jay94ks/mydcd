// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"

	"github.com/go-git/go-git/v5"
)

// DeliveryFetch identifies one read of the registered source. A fetch adapter
// authenticates its result and reads only this source before submitting it to
// the management FSM. A ticket is not Git/HTTP authentication or commit proof.
type DeliveryFetch struct {
	Sequence, PolicyRevision uint64
	Source                   [32]byte
}

type deliveryArtifact struct {
	Original           bool `json:",omitempty"` // file body is exact input, not regenerated legacy YAML
	Kind, Commit, Path string
	Digest             [32]byte
	Body               []byte
}

// DeliveryInput is created by the pinned object reader. No mutable checkout,
// caller-created Compose model or branch name is accepted as a pinned result.
type DeliveryInput struct {
	fetch    DeliveryFetch
	artifact deliveryArtifact
}

// Content is the immutable adapter result for the existing chunked artifact
// transport. It contains no Git credential and grants no management authority.
func (i DeliveryInput) Content() (commit, name string, body []byte) {
	return i.artifact.Commit, i.artifact.Path, bytes.Clone(i.artifact.Body)
}

// RestoreFetchedDeliveryInput validates received public artifact bytes. The
// control boundary MUST additionally verify the installed member's signed
// fetch attestation and current registered source ticket; this constructor
// alone is not proof that these bytes came from an HTTPS Git repository.
func RestoreFetchedDeliveryInput(ticket DeliveryFetch, commit, name string, body []byte, limit int64) (DeliveryInput, error) {
	if ticket.Sequence == 0 || ticket.PolicyRevision == 0 || ticket.Source == ([32]byte{}) || !gitCommit(commit) || !relativeFile(name) || limit < 1 || limit > 4<<20 || len(body) == 0 || int64(len(body)) > limit {
		return DeliveryInput{}, ErrSource
	}
	if _, err := ParseApp(body); err != nil {
		return DeliveryInput{}, ErrSource
	}
	return DeliveryInput{ticket, deliveryArtifact{Kind: "git", Commit: commit, Path: name, Digest: sha256.Sum256(body), Body: bytes.Clone(body)}}, nil
}

// ReadDeliveryInput is the read-only source boundary, outside deterministic
// transitions. E6 supplies an authorized fetched repository for ticket.Source.
// No fetch, credentials, clock, filesystem checkout or application execution.
func ReadDeliveryInput(repo *git.Repository, ticket DeliveryFetch, commit, name string, limit int64) (DeliveryInput, error) {
	if ticket.Sequence == 0 || ticket.PolicyRevision == 0 || ticket.Source == ([32]byte{}) {
		return DeliveryInput{}, ErrSource
	}
	a, err := ReadGitCompose(repo, commit, name, limit)
	if err != nil {
		return DeliveryInput{}, err
	}
	return DeliveryInput{ticket, deliveryArtifact{Kind: "git", Commit: a.Commit, Path: a.Path, Digest: a.Digest, Body: a.Bytes()}}, nil
}

func artifactCompose(a deliveryArtifact) (Compose, error) {
	return artifactComposeKind(a, "")
}

// Frozen candidates retain their original input contract when restoring a
// checkpoint. New candidates use app rules before normalization.
func artifactComposeKind(a deliveryArtifact, kind string) (Compose, error) {
	if a.Digest == ([32]byte{}) || len(a.Body) == 0 || len(a.Body) > 4<<20 || sha256.Sum256(a.Body) != a.Digest {
		return Compose{}, ErrSource
	}
	if a.Kind == "file" {
		if a.Commit != "" || a.Path != "" {
			return Compose{}, ErrSource
		}
	} else if a.Kind == "git" {
		if !gitCommit(a.Commit) || !relativeFile(a.Path) {
			return Compose{}, ErrSource
		}
	} else {
		return Compose{}, ErrSource
	}
	switch kind {
	case "app", "":
		return parsedDeliveryArtifacts.compose(a, kind)
	default:
		return Compose{}, ErrSource
	}
}
func gitCommit(id string) bool {
	if len(id) != 40 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func deliverySourceID(p DeliveryDeclaration) [32]byte {
	raw, _ := json.Marshal(p.Source)
	return sha256.Sum256(append([]byte("sfc-delivery-source-1\x00"), raw...))
}
