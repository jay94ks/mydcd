// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/jay94ks/seafield/internal/cluster/state"
)

// A checkpoint ("book") is one JSON object, stored so that a change writes
// only what it changed (R17 B2). Each element of a top-level array or object
// member that is itself an object or array of at least blobInline bytes is
// stored once as a content-addressed blob; the book's skeleton keeps a
// reference "@<sha256 hex>:<length>" in its place. The skeleton is a blob too,
// and the root object holds only its reference:
//
//	<root>                       checkpointRoot
//	<root>/<sha256 hex>/<i>      part i of a blob (blobPartSize each)
//
// An unchanged record keeps its blob, so a change writes the new skeleton,
// the blobs of the records it changed, and deletes the blobs no longer used.
// Blob keys are their content's digest, so reading verifies each blob.
//
// BootstrapKey binds the namespace's immutable trust anchor; a member
// directory uses TrustRoot.
type checkpointRoot struct {
	Schema                uint8
	Cluster, BootstrapKey [32]byte
	Revision              uint64
	Skeleton              string
}

const (
	blobPartSize = 32 << 10
	blobInline   = 128
)

func blobRef(value []byte) string {
	d := sha256.Sum256(value)
	return "@" + hex.EncodeToString(d[:]) + ":" + strconv.Itoa(len(value))
}

// parseBlobRef is the digest and length of a reference, or ok false.
func parseBlobRef(s string) (digest string, length int, ok bool) {
	if len(s) < 67 || s[0] != '@' || s[65] != ':' {
		return "", 0, false
	}
	digest = s[1:65]
	if _, err := hex.DecodeString(digest); err != nil || strings.ToLower(digest) != digest {
		return "", 0, false
	}
	length, err := strconv.Atoi(s[66:])
	if err != nil || length <= 0 || strconv.Itoa(length) != s[66:] {
		return "", 0, false
	}
	return digest, length, true
}

func blobParts(length int) int { return (length + blobPartSize - 1) / blobPartSize }

func blobPartKey(root, digest string, i int) string {
	return fmt.Sprintf("%s/%s/%d", root, digest, i)
}

// jsonMembers walks the members of a JSON object in order.
func jsonMembers(raw []byte, each func(key string, value json.RawMessage) error) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	if t, err := d.Token(); err != nil || t != json.Delim('{') {
		return ErrCatalog
	}
	for d.More() {
		t, err := d.Token()
		key, ok := t.(string)
		if err != nil || !ok {
			return ErrCatalog
		}
		var value json.RawMessage
		if err = d.Decode(&value); err != nil {
			return ErrCatalog
		}
		if err = each(key, value); err != nil {
			return err
		}
	}
	if t, err := d.Token(); err != nil || t != json.Delim('}') {
		return ErrCatalog
	}
	if _, err := d.Token(); err == nil {
		return ErrCatalog
	}
	return nil
}

func jsonElements(raw []byte, each func(value json.RawMessage) error) error {
	var values []json.RawMessage
	if json.Unmarshal(raw, &values) != nil {
		return ErrCatalog
	}
	for _, v := range values {
		if err := each(v); err != nil {
			return err
		}
	}
	return nil
}

func appendJSONKey(out []byte, key string) []byte {
	k, _ := json.Marshal(key)
	return append(append(out, k...), ':')
}

// collectionItem is one element of an array (key "" and array true) or one
// member of an object.
type collectionItem struct {
	key   string
	value json.RawMessage
}

// collectionItems is the items of a top-level array or object, or ok false
// for any other value.
func collectionItems(raw json.RawMessage) (items []collectionItem, array, ok bool, err error) {
	switch {
	case len(raw) > 0 && raw[0] == '[':
		err = jsonElements(raw, func(v json.RawMessage) error {
			items = append(items, collectionItem{value: v})
			return nil
		})
		return items, true, true, err
	case len(raw) > 0 && raw[0] == '{':
		err = jsonMembers(raw, func(k string, v json.RawMessage) error {
			items = append(items, collectionItem{k, v})
			return nil
		})
		return items, false, true, err
	}
	return nil, false, false, nil
}

func encodeCollection(items []collectionItem, array bool) json.RawMessage {
	open, end := byte('{'), byte('}')
	if array {
		open, end = '[', ']'
	}
	out := []byte{open}
	for i, item := range items {
		if i > 0 {
			out = append(out, ',')
		}
		if !array {
			out = appendJSONKey(out, item.key)
		}
		out = append(out, item.value...)
	}
	return append(out, end)
}

// groupKey marks a collection stored as groups: {"@g":[group refs]}.
const groupKey = "@g"

// groupMin is the least number of items a collection needs to be grouped.
// A group ends after an item whose reference digest starts with "00"..."03"
// (1 in 64), so groups average 64 items and an insertion or removal changes
// only its own group.
const groupMin = 128

func groupBoundary(item collectionItem) bool {
	var s string
	if json.Unmarshal(item.value, &s) != nil {
		return false
	}
	digest, _, ok := parseBlobRef(s)
	return ok && digest[0] == '0' && digest[1] <= '3'
}

func isGroups(raw json.RawMessage) ([]string, bool) {
	var g map[string][]string
	if len(raw) == 0 || raw[0] != '{' || json.Unmarshal(raw, &g) != nil || len(g) != 1 || g[groupKey] == nil {
		return nil, false
	}
	return g[groupKey], true
}

func isRefValue(v json.RawMessage) (string, bool) {
	var s string
	if len(v) == 0 || v[0] != '"' || json.Unmarshal(v, &s) != nil {
		return "", false
	}
	_, _, ok := parseBlobRef(s)
	return s, ok
}

// splitValue is the stored form of one top-level member value.
func splitValue(value json.RawMessage, blobs map[string][]byte) (json.RawMessage, error) {
	if _, grouped := isGroups(value); grouped {
		return nil, ErrCatalog
	}
	items, array, ok, err := collectionItems(value)
	if err != nil || !ok {
		return value, err
	}
	for i, item := range items {
		v := item.value
		if _, isRef := isRefValue(v); isRef {
			return nil, ErrCatalog
		}
		if len(v) >= blobInline && (v[0] == '{' || v[0] == '[') {
			ref := blobRef(v)
			blobs[ref] = bytes.Clone(v)
			items[i].value, _ = json.Marshal(ref)
		}
	}
	if len(items) < groupMin {
		return encodeCollection(items, array), nil
	}
	var refs []string
	for start := 0; start < len(items); {
		end := start
		for end < len(items)-1 && !groupBoundary(items[end]) {
			end++
		}
		group := encodeCollection(items[start:end+1], array)
		ref := blobRef(group)
		blobs[ref] = group
		refs = append(refs, ref)
		start = end + 1
	}
	return json.Marshal(map[string][]string{groupKey: refs})
}

// joinValue rebuilds one top-level member value from its stored form.
func joinValue(value json.RawMessage, get func(ref string) ([]byte, error)) (json.RawMessage, error) {
	var items []collectionItem
	var array bool
	if refs, grouped := isGroups(value); grouped {
		if len(refs) == 0 {
			return nil, ErrCatalog
		}
		for i, ref := range refs {
			raw, err := get(ref)
			if err != nil {
				return nil, err
			}
			part, partArray, ok, err := collectionItems(raw)
			if err != nil || !ok || i > 0 && partArray != array {
				return nil, ErrCatalog
			}
			items, array = append(items, part...), partArray
		}
	} else {
		var ok bool
		var err error
		items, array, ok, err = collectionItems(value)
		if err != nil || !ok {
			return value, err
		}
	}
	for i, item := range items {
		if ref, isRef := isRefValue(item.value); isRef {
			v, err := get(ref)
			if err != nil {
				return nil, err
			}
			items[i].value = v
		}
	}
	return encodeCollection(items, array), nil
}

// splitCheckpoint is the skeleton of raw and the blobs it references.
func splitCheckpoint(raw []byte) ([]byte, map[string][]byte, error) {
	blobs := map[string][]byte{}
	var members []collectionItem
	err := jsonMembers(raw, func(key string, value json.RawMessage) error {
		v, err := splitValue(value, blobs)
		members = append(members, collectionItem{key, v})
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	return encodeCollection(members, false), blobs, nil
}

// joinCheckpoint rebuilds a book from its skeleton, reading blobs by get.
func joinCheckpoint(skeleton []byte, get func(ref string) ([]byte, error)) ([]byte, error) {
	var members []collectionItem
	err := jsonMembers(skeleton, func(key string, value json.RawMessage) error {
		v, err := joinValue(value, get)
		members = append(members, collectionItem{key, v})
		return err
	})
	if err != nil {
		return nil, err
	}
	return encodeCollection(members, false), nil
}

// storedRefs is every blob reference the book stored at key uses, read
// without its record blobs: the skeleton, its groups and their references.
func storedRefs(s state.State, key string) (map[string]bool, error) {
	var header checkpointRoot
	root := s.Object(key)
	if !root.Present || canonical([]byte(root.Value), &header) != nil {
		return nil, ErrCatalog
	}
	objects := s.Objects(key + "/")
	skeleton, err := readBlob(objects, key, header.Skeleton, map[string]bool{})
	if err != nil {
		return nil, err
	}
	refs := map[string]bool{header.Skeleton: true}
	items := func(raw json.RawMessage) error {
		list, _, _, err := collectionItems(raw)
		for _, item := range list {
			if ref, ok := isRefValue(item.value); ok {
				refs[ref] = true
			}
		}
		return err
	}
	err = jsonMembers(skeleton, func(_ string, value json.RawMessage) error {
		groups, grouped := isGroups(value)
		if !grouped {
			return items(value)
		}
		for _, ref := range groups {
			raw, err := readBlob(objects, key, ref, map[string]bool{})
			if err != nil {
				return err
			}
			refs[ref] = true
			if err = items(raw); err != nil {
				return err
			}
		}
		return nil
	})
	return refs, err
}

func readBlob(objects map[string]state.Object, root, ref string, used map[string]bool) ([]byte, error) {
	digest, length, ok := parseBlobRef(ref)
	if !ok {
		return nil, ErrCatalog
	}
	value := make([]byte, 0, length)
	for i := 0; i < blobParts(length); i++ {
		key := blobPartKey(root, digest, i)
		part := objects[key]
		want := min(blobPartSize, length-len(value))
		if !part.Present || len(part.Value) != want {
			return nil, ErrCatalog
		}
		value = append(value, part.Value...)
		used[key] = true
	}
	if blobRef(value) != ref {
		return nil, ErrCatalog
	}
	return value, nil
}

func readCheckpoint(s state.State, key string, cluster, anchor [32]byte) ([]byte, uint64, error) {
	if cluster == ([32]byte{}) || anchor == ([32]byte{}) {
		return nil, 0, ErrCatalog
	}
	root := s.Object(key)
	objects := s.Objects(key + "/")
	if root.Revision == 0 {
		for _, o := range objects {
			if o.Present {
				return nil, 0, ErrCatalog
			}
		}
		return nil, 0, nil
	}
	var header checkpointRoot
	if !root.Present || canonical([]byte(root.Value), &header) != nil || header.Schema != 2 || header.Cluster != cluster || header.BootstrapKey != anchor || header.Revision == 0 {
		return nil, 0, ErrCatalog
	}
	used := map[string]bool{}
	skeleton, err := readBlob(objects, key, header.Skeleton, used)
	if err != nil {
		return nil, 0, err
	}
	raw, err := joinCheckpoint(skeleton, func(ref string) ([]byte, error) { return readBlob(objects, key, ref, used) })
	if err != nil {
		return nil, 0, ErrCatalog
	}
	for k, o := range objects {
		if o.Present && !used[k] {
			return nil, 0, ErrCatalog
		}
	}
	return raw, header.Revision, nil
}

// checkpointPatchKey reports whether key belongs to the checkpoint written
// at root by this reduction: the root itself, or one of its blob parts. A
// part may be removed (nil), because a change deletes the blobs it no longer
// uses; the root is never removed.
func checkpointPatchKey(writes map[string][]byte, root, key string) bool {
	value, written := writes[key]
	if key == root {
		return written && value != nil
	}
	return written && strings.HasPrefix(key, root+"/")
}

func writeCheckpoint(s state.State, key string, cluster, anchor [32]byte, revision uint64, raw []byte) (map[string][]byte, state.Code) {
	if len(raw) == 0 || revision == 0 {
		return nil, state.Invalid
	}
	skeleton, blobs, err := splitCheckpoint(raw)
	if err != nil {
		return nil, state.Invalid
	}
	// The stored form must rebuild exactly these bytes.
	if again, err := joinCheckpoint(skeleton, func(ref string) ([]byte, error) { return blobs[ref], nil }); err != nil || !bytes.Equal(again, raw) {
		return nil, state.Invalid
	}
	self := blobRef(skeleton)
	blobs[self] = skeleton
	// The blobs the stored book uses now. A blank or unreadable book has
	// none; any other object under the root is deleted below.
	old := map[string]bool{}
	if refs, err := storedRefs(s, key); err == nil {
		old = refs
	}
	writes := map[string][]byte{}
	keep := map[string]bool{}
	for ref, value := range blobs {
		digest, length, _ := parseBlobRef(ref)
		for i := 0; i < blobParts(length); i++ {
			part := blobPartKey(key, digest, i)
			keep[part] = true
			if !old[ref] {
				end := min(len(value), (i+1)*blobPartSize)
				writes[part] = bytes.Clone(value[i*blobPartSize : end])
			}
		}
	}
	for ref := range old {
		if blobs[ref] != nil {
			continue
		}
		digest, length, _ := parseBlobRef(ref)
		for i := 0; i < blobParts(length); i++ {
			writes[blobPartKey(key, digest, i)] = nil
		}
	}
	if len(old) == 0 {
		for part, o := range s.Objects(key + "/") {
			if o.Present && !keep[part] {
				writes[part] = nil
			}
		}
	}
	for part, value := range writes {
		if value == nil && !s.Object(part).Present {
			delete(writes, part)
		}
	}
	writes[key], err = json.Marshal(checkpointRoot{2, cluster, anchor, revision, self})
	if err != nil {
		return nil, state.Invalid
	}
	return writes, state.Applied
}
