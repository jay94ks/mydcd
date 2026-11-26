// SPDX-License-Identifier: Apache-2.0

// Package imagecache describes explicit, bounded node-local Docker cache work.
// Images are immutable content IDs; a plan is observation, not delete authority.
package imagecache

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/distribution/reference"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
)

const MaxImages = 8

var ErrPlan = errors.New("invalid, changed or unavailable image cache plan")

func ValidID(id string) bool {
	if len(id) != 71 || !strings.HasPrefix(id, "sha256:") {
		return false
	}
	bytes, err := hex.DecodeString(id[7:])
	return err == nil && len(bytes) == 32 && hex.EncodeToString(bytes) == id[7:]
}
func CanonicalReference(value string) (string, error) {
	if ValidID(value) {
		return value, nil
	}
	if len(value) > 512 || strings.ContainsAny(value, "\x00\r\n") {
		return "", ErrPlan
	}
	n, err := reference.ParseNormalizedNamed(value)
	if err != nil {
		return "", ErrPlan
	}
	return n.String(), nil
}
func ValidSelection(ids []string, required bool) bool {
	if len(ids) > MaxImages || required && len(ids) == 0 {
		return false
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if !ValidID(id) || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}

type Query struct {
	Node, After, Operation string
	Images                 []string `json:",omitempty"`
}

func (q Query) Valid(plan bool) bool {
	if !plan {
		return lifecycle.ValidID(q.Operation) && q.Node == "" && q.After == "" && len(q.Images) == 0
	}
	return lifecycle.ValidID(q.Node) && q.Operation == "" && ValidSelection(q.Images, false) && (q.After == "" || len(q.Images) == 0 && ValidID(q.After))
}

type Image struct {
	ID                     string
	Aliases                []string
	Bytes                  int64
	Containers, References uint64
}

func (i Image) Valid() bool {
	if !ValidID(i.ID) || i.Bytes < 0 || len(i.Aliases) > 32 {
		return false
	}
	for n, a := range i.Aliases {
		canonical, err := CanonicalReference(a)
		if err != nil || a != canonical || a == i.ID || n > 0 && i.Aliases[n-1] >= a {
			return false
		}
	}
	return true
}
func (i Image) Unused() bool { return i.Valid() && i.Containers == 0 && i.References == 0 }
func (i Image) Matches(ref string) bool {
	r, err := CanonicalReference(ref)
	return err == nil && (r == i.ID || slices.Contains(i.Aliases, r))
}
func (i Image) SameContent(other Image) bool {
	return i.ID == other.ID && i.Bytes == other.Bytes && slices.Equal(i.Aliases, other.Aliases)
}

type Plan struct {
	Schema               uint8
	Cluster, Owner, Boot [32]byte
	Node                 string
	At, Index            uint64   // UTC milliseconds; owner's observed shared command prefix
	Selection            []string `json:",omitempty"`
	Images               []Image
	Next                 string
	Signature            []byte
}

func PlanBytes(p Plan) []byte {
	p.Signature = nil
	raw, _ := json.Marshal(p)
	return append([]byte("mydc-image-cache-plan-1\x00"), raw...)
}
func (p Plan) Digest() [32]byte {
	raw, _ := json.Marshal(p)
	return sha256.Sum256(append([]byte("mydc-image-cache-target-1\x00"), raw...))
}
func (p Plan) Valid() bool {
	if p.Schema != 1 || p.Cluster == ([32]byte{}) || p.Owner == ([32]byte{}) || p.Boot == ([32]byte{}) || !lifecycle.ValidID(p.Node) || p.At == 0 || p.Index == 0 || !ValidSelection(p.Selection, false) || len(p.Images) > MaxImages || p.Next != "" && (len(p.Selection) > 0 || !ValidID(p.Next)) || len(p.Selection) > 0 && len(p.Images) != len(p.Selection) {
		return false
	}
	for i, image := range p.Images {
		if !image.Valid() || i > 0 && p.Images[i-1].ID >= image.ID {
			return false
		}
	}
	for i, id := range p.Selection {
		if i > 0 && p.Selection[i-1] >= id || p.Images[i].ID != id {
			return false
		}
	}
	if p.Next != "" && (len(p.Images) == 0 || p.Next != p.Images[len(p.Images)-1].ID) {
		return false
	}
	raw, err := json.Marshal(p)
	return err == nil && len(raw) <= 24<<10 && ed25519.Verify(p.Owner[:], PlanBytes(p), p.Signature)
}
func (p Plan) DeleteReady() bool {
	if !p.Valid() || len(p.Selection) == 0 || p.Next != "" {
		return false
	}
	for _, image := range p.Images {
		if !image.Unused() {
			return false
		}
	}
	return true
}

type Part struct {
	ID, State, Code, Error string
	At                     uint64
}

func (p Part) Valid() bool {
	if !ValidID(p.ID) || p.At == 0 || len(p.Error) > 512 || !utf8.ValidString(p.Error) || len(p.Code) > 64 || strings.ContainsAny(p.Code, "\x00\r\n") {
		return false
	}
	switch p.State {
	case "removed", "already-absent":
		return p.Code == "" && p.Error == ""
	case "failed", "skipped":
		return p.Code != ""
	}
	return false
}

type Change struct {
	Operation string
	Plan      Plan
}

func (c Change) Valid() bool { return lifecycle.ValidID(c.Operation) && c.Plan.DeleteReady() }
