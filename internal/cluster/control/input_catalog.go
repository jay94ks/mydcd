// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding"
	"encoding/json"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"time"
)

// InputAction describes one action `sfcli manage apply` accepts: its name,
// the CAS namespace its Expected is compared in, and the payload fields as
// InputChange decodes them. A screen builds the change from this without a
// change file.
type InputAction struct {
	Action string       `json:"action"`
	Key    string       `json:"key"`
	Fields []InputField `json:"fields"`
}

// InputField is one payload field. Type is string, integer, boolean, bytes
// (base64), json (any JSON), list (Items), map (string keys, Items) or object
// (Fields). Replace marks a field that replaces a whole value: it is always
// sent, an empty list as [] (explicitFields).
type InputField struct {
	Name    string       `json:"name,omitempty"` // empty for list and map items
	Type    string       `json:"type"`
	Format  string       `json:"format,omitempty"`
	Length  int          `json:"length,omitempty"` // a fixed-length list (an array)
	Replace bool         `json:"replace,omitempty"`
	Items   *InputField  `json:"items,omitempty"`
	Fields  []InputField `json:"fields,omitempty"`
}

// InputActions lists every accepted action, sorted by name.
func InputActions() []InputAction {
	out := make([]InputAction, 0, len(inputPayloads))
	for action, t := range inputPayloads {
		f := describeType(t, map[reflect.Type]bool{})
		a := InputAction{Action: action, Key: strings.TrimPrefix(CommandKey(action), "control/"), Fields: f.Fields}
		if a.Fields == nil {
			a.Fields = []InputField{}
		}
		for i := range a.Fields {
			a.Fields[i].Replace = slices.Contains(replacedFields[action], a.Fields[i].Name)
		}
		out = append(out, a)
	}
	slices.SortFunc(out, func(a, b InputAction) int { return strings.Compare(a.Action, b.Action) })
	return out
}

var (
	textMarshaler = reflect.TypeFor[encoding.TextMarshaler]()
	jsonMarshaler = reflect.TypeFor[json.Marshaler]()
	textFormats   = map[reflect.Type]string{
		reflect.TypeFor[netip.Prefix]():   "cidr",
		reflect.TypeFor[netip.Addr]():     "ip",
		reflect.TypeFor[netip.AddrPort](): "ip-port",
		reflect.TypeFor[time.Time]():      "time",
	}
)

func implements(t, iface reflect.Type) bool {
	return t.Implements(iface) || reflect.PointerTo(t).Implements(iface)
}

// describeType follows encoding/json's rules for t. A type with its own
// JSON or text form, or one met again inside itself, is described by that
// form only.
func describeType(t reflect.Type, open map[reflect.Type]bool) InputField {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == reflect.TypeFor[json.RawMessage]() {
		return InputField{Type: "json"}
	}
	if implements(t, jsonMarshaler) {
		return InputField{Type: "json"}
	}
	if implements(t, textMarshaler) {
		return InputField{Type: "string", Format: textFormats[t]}
	}
	if t == reflect.TypeFor[time.Duration]() {
		return InputField{Type: "integer", Format: "duration"}
	}
	switch t.Kind() {
	case reflect.String:
		return InputField{Type: "string"}
	case reflect.Bool:
		return InputField{Type: "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return InputField{Type: "integer"}
	case reflect.Float32, reflect.Float64:
		return InputField{Type: "number"}
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 && !implements(t.Elem(), jsonMarshaler) && !implements(t.Elem(), textMarshaler) {
			return InputField{Type: "bytes"}
		}
		items := describeType(t.Elem(), open)
		return InputField{Type: "list", Items: &items}
	case reflect.Array:
		items := describeType(t.Elem(), open)
		return InputField{Type: "list", Items: &items, Length: t.Len()}
	case reflect.Map:
		items := describeType(t.Elem(), open)
		return InputField{Type: "map", Items: &items}
	case reflect.Struct:
		if open[t] {
			return InputField{Type: "json"}
		}
		open[t] = true
		defer delete(open, t)
		return InputField{Type: "object", Fields: structFields(t, open)}
	}
	return InputField{Type: "json"}
}

func structFields(t reflect.Type, open map[reflect.Type]bool) []InputField {
	var out []InputField
	for i := 0; i < t.NumField(); i++ {
		sf := t.Field(i)
		tag := sf.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if sf.Anonymous && name == "" {
			et := sf.Type
			if et.Kind() == reflect.Pointer {
				et = et.Elem()
			}
			if et.Kind() == reflect.Struct && !implements(et, jsonMarshaler) && !implements(et, textMarshaler) {
				out = append(out, structFields(et, open)...)
				continue
			}
		}
		if !sf.IsExported() {
			continue
		}
		if name == "" {
			name = sf.Name
		}
		f := describeType(sf.Type, open)
		f.Name = name
		out = append(out, f)
	}
	return out
}

// InputActionType reports the payload type of an accepted action.
func InputActionType(action string) (reflect.Type, bool) {
	t, ok := inputPayloads[action]
	return t, ok
}
