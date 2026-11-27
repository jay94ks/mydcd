// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"encoding/json"

	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
)

const appSourceInputMaxBytes = 8 << 20
const appSourceFactsMaxBytes = 2 << 20

// The explicit SourceEnvelope flag binds this format to the existing ordered,
// hashed, EOF-checked User input stream. app.yaml itself still has no facts.
type appSourceInput struct {
	Document []byte
	Sources  map[string]json.RawMessage
}

func encodeAppSourceInput(document []byte, facts map[string]checker.SourceFact, cluster [32]byte, tenant string) ([]byte, error) {
	if len(document) == 0 || len(document) > deployment.ArtifactMaxBytes || len(facts) == 0 || len(facts) > checker.MaxScripts {
		return nil, sfcp.ErrBudget
	}
	input := appSourceInput{Document: document, Sources: map[string]json.RawMessage{}}
	total := 0
	for alias, fact := range facts {
		if !checker.ValidScriptName(alias) || fact.Cluster != cluster || fact.Tenant != tenant || fact.Verify() != nil {
			return nil, sfcp.ErrAdmission
		}
		raw, err := json.Marshal(fact)
		if err != nil || len(raw) > 16<<10 {
			return nil, sfcp.ErrBudget
		}
		total += len(alias) + len(raw)
		if total > appSourceFactsMaxBytes {
			return nil, sfcp.ErrBudget
		}
		input.Sources[alias] = raw
	}
	raw, err := json.Marshal(input)
	if err != nil || len(raw) > appSourceInputMaxBytes {
		return nil, sfcp.ErrBudget
	}
	return raw, nil
}

func decodeAppSourceInput(raw []byte, cluster [32]byte, tenant string) ([]byte, map[string]checker.SourceFact, error) {
	if len(raw) == 0 || len(raw) > appSourceInputMaxBytes {
		return nil, nil, sfcp.ErrBudget
	}
	input, err := schema.Decode[appSourceInput](raw)
	accepted := false
	defer func() {
		if !accepted {
			clear(input.Document)
		}
	}()
	if err != nil || len(input.Document) == 0 || len(input.Document) > deployment.ArtifactMaxBytes || len(input.Sources) == 0 || len(input.Sources) > checker.MaxScripts {
		return nil, nil, sfcp.ErrAdmission
	}
	facts := make(map[string]checker.SourceFact, len(input.Sources))
	total := 0
	for alias, encoded := range input.Sources {
		total += len(alias) + len(encoded)
		if !checker.ValidScriptName(alias) || len(encoded) > 16<<10 || total > appSourceFactsMaxBytes {
			return nil, nil, sfcp.ErrBudget
		}
		fact, err := schema.InputLimit[checker.SourceFact](encoded, 16<<10)
		if err != nil || fact.Cluster != cluster || fact.Tenant != tenant || fact.Verify() != nil {
			return nil, nil, sfcp.ErrAdmission
		}
		// Each signed fact has its canonical shape, not a human JSON variant.
		canonical, _ := json.Marshal(fact)
		if !bytes.Equal(canonical, encoded) {
			return nil, nil, sfcp.ErrAdmission
		}
		facts[alias] = fact
	}
	accepted = true
	return input.Document, facts, nil
}
