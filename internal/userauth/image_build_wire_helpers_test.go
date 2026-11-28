// SPDX-License-Identifier: Apache-2.0

package userauth

import "encoding/json"

// typedParams decodes a fake server's typed request strictly into p, and
// reports whether it is method's request with nothing but its Params.
func typedParams[P any](request Request, method string, p *P) bool {
	if request.Method != method || !request.validMethodFields() || !request.validQuerySelectors() || strict(request.Params, p) != nil {
		return false
	}
	_, typed, ok := request.typedMethod()
	return typed && ok
}

// okReply carries out as a typed reply's Data.
func okReply(out any) Reply {
	data, err := json.Marshal(out)
	if err != nil {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	return Reply{Schema: 1, Code: "ok", Data: data}
}
