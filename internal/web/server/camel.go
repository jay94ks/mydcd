// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"time"
	"unicode"

	"github.com/jay94ks/seafield/internal/access"
)

// camelJSON encodes v the way /api/v1 presents sfcd views to the browser:
// struct field names become lowerCamelCase (an explicit json tag name wins,
// omitempty/"-" are honored, embedded structs are flattened), map keys are
// kept verbatim (they are user data such as secret key names), fixed-size
// byte arrays (keys, digests) become hex strings, []byte becomes base64, and
// time.Time becomes RFC 3339.
func camelJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := encodeCamel(&buf, reflect.ValueOf(v)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// camel is a value marshaled with camelJSON when it is inside writeJSON.
type camel struct{ v any }

func (c camel) MarshalJSON() ([]byte, error) { return camelJSON(c.v) }

var (
	timeType       = reflect.TypeFor[time.Time]()
	marshalerType  = reflect.TypeFor[json.Marshaler]()
	rawMessageType = reflect.TypeFor[json.RawMessage]()
	// wireStructs implement MarshalJSON only to keep sfcd's stored bytes
	// (nil vs empty VolumeFiles). The browser view encodes them field by
	// field like any other struct. Every other Marshaler is honored, above
	// all the ones that refuse to encode private material.
	wireStructs = map[reflect.Type]bool{
		reflect.TypeFor[access.Credential]():       true,
		reflect.TypeFor[access.PublicCredential](): true,
	}
)

func encodeCamel(buf *bytes.Buffer, v reflect.Value) error {
	if !v.IsValid() {
		buf.WriteString("null")
		return nil
	}
	t := v.Type()
	switch {
	case t == timeType:
		return writeStd(buf, v.Interface().(time.Time).UTC().Format(time.RFC3339))
	case t == rawMessageType:
		if v.Len() == 0 {
			buf.WriteString("null")
			return nil
		}
		buf.Write(v.Bytes())
		return nil
	case t.Kind() != reflect.Pointer && t.Kind() != reflect.Interface && t.Implements(marshalerType) && !wireStructs[t]:
		return writeStd(buf, v.Interface())
	}
	switch t.Kind() {
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			buf.WriteString("null")
			return nil
		}
		return encodeCamel(buf, v.Elem())
	case reflect.Struct:
		return encodeStruct(buf, v)
	case reflect.Map:
		if v.IsNil() {
			buf.WriteString("null")
			return nil
		}
		buf.WriteByte('{')
		keys := v.MapKeys()
		strs := make([]string, len(keys))
		for i, k := range keys {
			strs[i] = mapKeyString(k)
		}
		order := sortedIndex(strs)
		for n, i := range order {
			if n > 0 {
				buf.WriteByte(',')
			}
			if err := writeStd(buf, strs[i]); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := encodeCamel(buf, v.MapIndex(keys[i])); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
		return nil
	case reflect.Array:
		if t.Elem().Kind() == reflect.Uint8 {
			b := make([]byte, v.Len())
			reflect.Copy(reflect.ValueOf(b), v)
			return writeStd(buf, hex.EncodeToString(b))
		}
		return encodeList(buf, v)
	case reflect.Slice:
		if v.IsNil() {
			if t.Elem().Kind() == reflect.Uint8 {
				buf.WriteString("null")
			} else {
				buf.WriteString("[]")
			}
			return nil
		}
		if t.Elem().Kind() == reflect.Uint8 {
			return writeStd(buf, base64.StdEncoding.EncodeToString(v.Bytes()))
		}
		return encodeList(buf, v)
	default:
		return writeStd(buf, v.Interface())
	}
}

func encodeList(buf *bytes.Buffer, v reflect.Value) error {
	buf.WriteByte('[')
	for i := 0; i < v.Len(); i++ {
		if i > 0 {
			buf.WriteByte(',')
		}
		if err := encodeCamel(buf, v.Index(i)); err != nil {
			return err
		}
	}
	buf.WriteByte(']')
	return nil
}

type camelField struct {
	name      string
	index     []int
	omitEmpty bool
}

func structFields(t reflect.Type) []camelField {
	var out []camelField
	seen := map[string]bool{}
	var walk func(t reflect.Type, index []int)
	walk = func(t reflect.Type, index []int) {
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			idx := append(append([]int(nil), index...), i)
			tag := f.Tag.Get("json")
			if tag == "-" {
				continue
			}
			name, opts, _ := strings.Cut(tag, ",")
			if f.Anonymous && name == "" {
				ft := f.Type
				if ft.Kind() == reflect.Pointer {
					ft = ft.Elem()
				}
				if ft.Kind() == reflect.Struct {
					walk(ft, idx)
					continue
				}
			}
			if !f.IsExported() {
				continue
			}
			if name == "" {
				name = lowerCamel(f.Name)
			}
			if seen[name] {
				continue
			}
			seen[name] = true
			out = append(out, camelField{name: name, index: idx, omitEmpty: strings.Contains(opts, "omitempty") || strings.Contains(opts, "omitzero")})
		}
	}
	walk(t, nil)
	return out
}

func encodeStruct(buf *bytes.Buffer, v reflect.Value) error {
	buf.WriteByte('{')
	first := true
	// A wire struct's empty-but-set list keeps its meaning (VolumeFiles []
	// = deny all, nil = no ceiling), so only nil is omitted there.
	keepEmpty := wireStructs[v.Type()]
	for _, f := range structFields(v.Type()) {
		fv, ok := fieldByIndex(v, f.index)
		if !ok {
			continue
		}
		if f.omitEmpty && fv.IsZero() {
			continue
		}
		if f.omitEmpty && (fv.Kind() == reflect.Slice || fv.Kind() == reflect.Map) && fv.Len() == 0 && !(keepEmpty && !fv.IsNil()) {
			continue
		}
		if !first {
			buf.WriteByte(',')
		}
		first = false
		if err := writeStd(buf, f.name); err != nil {
			return err
		}
		buf.WriteByte(':')
		if err := encodeCamel(buf, fv); err != nil {
			return err
		}
	}
	buf.WriteByte('}')
	return nil
}

func fieldByIndex(v reflect.Value, index []int) (reflect.Value, bool) {
	for i, x := range index {
		if i > 0 && v.Kind() == reflect.Pointer {
			if v.IsNil() {
				return reflect.Value{}, false
			}
			v = v.Elem()
		}
		v = v.Field(x)
	}
	return v, true
}

// lowerCamel lowercases the leading capital run: ID→id, CPUPercent→cpuPercent,
// NodeID→nodeID, URLs→urls.
func lowerCamel(s string) string {
	runes := []rune(s)
	n := 0
	for n < len(runes) && unicode.IsUpper(runes[n]) {
		n++
	}
	switch {
	case n == 0:
		return s
	case n == 1 || n == len(runes):
		for i := 0; i < n; i++ {
			runes[i] = unicode.ToLower(runes[i])
		}
	default:
		// keep the last capital of the run as the start of the next word,
		// unless what follows is a lowercase plural "s" (URLs).
		end := n - 1
		if n < len(runes) && runes[n] == 's' && n+1 == len(runes) {
			end = n
		}
		for i := 0; i < end; i++ {
			runes[i] = unicode.ToLower(runes[i])
		}
	}
	return string(runes)
}

func mapKeyString(k reflect.Value) string {
	if k.Kind() == reflect.String {
		return k.String()
	}
	b, _ := json.Marshal(k.Interface())
	s := string(b)
	if len(s) >= 2 && s[0] == '"' {
		s = s[1 : len(s)-1]
	}
	return s
}

func sortedIndex(s []string) []int {
	idx := make([]int, len(s))
	for i := range idx {
		idx[i] = i
	}
	for i := 1; i < len(idx); i++ {
		for j := i; j > 0 && s[idx[j]] < s[idx[j-1]]; j-- {
			idx[j], idx[j-1] = idx[j-1], idx[j]
		}
	}
	return idx
}

func writeStd(buf *bytes.Buffer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	buf.Write(b)
	return nil
}
