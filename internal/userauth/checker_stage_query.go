// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"encoding/json"

	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
)

// CheckerStageQuery is the header of one lifecycle or checker script upload
// or recover: the script descriptor, the module pin for a module method and
// the client's upload ID. Its body, when there is one, follows as input
// frames after "continue".
type CheckerStageQuery struct {
	Tenant string
	// Node is the provider server; lifecycle-* only, required to recover.
	Node   string `json:",omitempty"`
	Source checker.SourceDescriptor
	Module *checker.ModulePin `json:",omitempty"`
	Upload [32]byte
}

func (q CheckerStageQuery) Valid() bool {
	return q.Tenant != "" && (q.Node == "" || safeID(q.Node)) && q.Source.Validate() == nil && q.Source.Tenant == q.Tenant && q.Upload != ([32]byte{}) && (q.Module == nil || moduleInput(q.Source, *q.Module))
}

// validFor adds what each method fixes: a module pin exactly for module
// methods, a provider node only for lifecycle methods and always to recover.
func (q CheckerStageQuery) validFor(method string) bool {
	if !q.Valid() || (q.Module != nil) != moduleMethod(method) {
		return false
	}
	switch method {
	case "lifecycle-source-stage", "lifecycle-module-stage":
		return true
	case "lifecycle-source-recover", "lifecycle-module-recover":
		return q.Node != ""
	case "checker-source-stage", "checker-module-stage", "checker-source-recover", "checker-module-recover":
		return q.Node == ""
	}
	return false
}

func moduleMethod(method string) bool {
	return method == "lifecycle-module-stage" || method == "lifecycle-module-recover" || method == "checker-module-stage" || method == "checker-module-recover"
}

func recoverMethod(method string) bool {
	return method == "lifecycle-source-recover" || method == "lifecycle-module-recover" || method == "checker-source-recover" || method == "checker-module-recover"
}

// The lifecycle editor methods answer "continue" (stage) and the final reply
// with a LifecycleStageResult in Data; the checker methods answer the fact.
var (
	LifecycleSourceStageMethod   = defineRoute(Method[CheckerStageQuery, LifecycleStageResult]{Name: "lifecycle-source-stage"}, false)
	LifecycleModuleStageMethod   = defineRoute(Method[CheckerStageQuery, LifecycleStageResult]{Name: "lifecycle-module-stage"}, false)
	LifecycleSourceRecoverMethod = defineRoute(Method[CheckerStageQuery, LifecycleStageResult]{Name: "lifecycle-source-recover"}, true)
	LifecycleModuleRecoverMethod = defineRoute(Method[CheckerStageQuery, LifecycleStageResult]{Name: "lifecycle-module-recover"}, true)
	CheckerSourceStageMethod     = defineRoute(Method[CheckerStageQuery, checker.SourceFact]{Name: "checker-source-stage"}, false)
	CheckerSourceRecoverMethod   = defineRoute(Method[CheckerStageQuery, checker.SourceFact]{Name: "checker-source-recover"}, true)
	CheckerModuleStageMethod     = defineRoute(Method[CheckerStageQuery, checker.ModuleFact]{Name: "checker-module-stage"}, false)
	CheckerModuleRecoverMethod   = defineRoute(Method[CheckerStageQuery, checker.ModuleFact]{Name: "checker-module-recover"}, true)
)

// checkerStage is the request's decoded header when it is one of these
// methods in its typed shape.
func (r Request) checkerStage() (CheckerStageQuery, bool) {
	rule, typed, ok := r.typedMethod()
	if !typed || !ok {
		return CheckerStageQuery{}, false
	}
	p, _ := rule.decode(r.Params)
	q, is := p.(CheckerStageQuery)
	return q, is && q.validFor(r.Method)
}

// stageRequest is the wire request of method with q as Params.
func stageRequest(method string, q CheckerStageQuery) (Request, error) {
	params, err := json.Marshal(q)
	return Request{Method: method, Params: params}, err
}

// dataReply marshals v into a reply's Data.
func dataReply(code string, v any) Reply {
	data, err := json.Marshal(v)
	if err != nil {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	return Reply{Schema: 1, Code: code, Data: data}
}
