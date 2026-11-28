// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/jay94ks/seafield/internal/web/store"
)

// Incident text kept as phrases (texts.go) and made into words when read,
// in the reader's language. Rows stored before the phrases keep their
// Korean text.

// entry is one timeline line.
func entry(at time.Time, kind string, p store.Phrase) store.IncidentEntry {
	return store.IncidentEntry{At: at, Kind: kind, Phrase: &p}
}

// actionPhrase names a candidate: an action of the fixed list by its id,
// anything else (an MCP tool) by its own label.
func actionPhrase(id, label string) store.Phrase {
	if incidentActionByID(id) != nil {
		return ph("incident-action." + id)
	}
	return lit(label)
}

// skipPhrase is "action: why" for a candidate left out.
func skipPhrase(action, why store.Phrase) store.Phrase {
	return with(with(ph("incident-skip"), "action", action), "why", why)
}

// titlePhrase is the incident's title: its rule's title and where (the
// stored Title when the rule is not known).
func titlePhrase(in *store.Incident) store.Phrase {
	if _, ok := incidentRules[in.Signal]; !ok {
		return lit(in.Title)
	}
	return with(ph("incident.title", "where", incidentWhere(in)), "rule", ph("incident-rule."+in.Signal+".title"))
}

// rulePhrase is the rule that fired, in words.
func rulePhrase(in *store.Incident) store.Phrase {
	if _, ok := incidentRules[in.Signal]; !ok {
		return lit(in.Rule)
	}
	return ph("incident-rule." + in.Signal + ".words")
}

// notePhrase is the decision's note (the stored Korean Note before
// NoteText).
func notePhrase(d store.IncidentDecision) store.Phrase {
	if d.NoteText != nil {
		return *d.NoteText
	}
	return lit(d.Note)
}

// approvalNotice is the approval request sent to the people who approve.
func approvalNotice(in *store.Incident) *store.NoticeText {
	n := notice("incident-approval", nil)
	note := notePhrase(in.Decision)
	if render(langKorean, note) != "" {
		n.Body = []string{"incident-approval.note"}
	}
	n.Phrases = map[string]store.Phrase{"title": titlePhrase(in), "note": note}
	return n
}

// actionLabel is a candidate's label in lang.
func actionLabel(lang string, a *store.IncidentAction) string {
	if a.MCP == nil && incidentActionByID(a.ID) != nil {
		return text(lang, "incident-action."+a.ID, nil)
	}
	return a.Label
}

// actionNote is a candidate's note in lang.
func actionNote(lang string, a *store.IncidentAction) string {
	return renderPtr(lang, a.NoteText, a.Note)
}

// impactText is the impact level in lang.
func impactText(lang, level string) string { return render(lang, impactPhrase(level)) }

// timelineIn is the timeline with each line's text in lang. Inputs and
// Reason are codes or values (text leaves a value as it is).
func timelineIn(lang string, lines []store.IncidentEntry) []store.IncidentEntry {
	out := make([]store.IncidentEntry, len(lines))
	for i, e := range lines {
		e.Text = renderPtr(lang, e.Phrase, e.Text)
		e.Phrase = nil
		e.Reason = reasonText(lang, e.Reason) // a reason code, or what a webhook said
		if len(e.Inputs) > 0 {
			in := make([]string, len(e.Inputs))
			for j, x := range e.Inputs {
				in[j] = text(lang, x, nil)
			}
			e.Inputs = in
		}
		out[i] = e
	}
	return out
}

// approvalCard is the pending approval's title and fields in lang.
func approvalCard(lang string, in *store.Incident) (string, []store.AIPreviewRow) {
	a := chosenAction(in)
	if a == nil {
		return in.Approval.Title, in.Approval.Fields
	}
	f := func(code string) string { return text(lang, "incident-field."+code, nil) }
	fields := []store.AIPreviewRow{{Label: f("action"), Value: actionLabel(lang, a)}, {Label: f("target"), Value: incidentWhere(in)},
		{Label: f("impact"), Value: impactText(lang, in.Impact)}, {Label: f("rule"), Value: render(lang, rulePhrase(in))}}
	if note := actionNote(lang, a); note != "" {
		fields = append(fields, store.AIPreviewRow{Label: f("note"), Value: note})
	}
	return actionLabel(lang, a), fields
}

// The Korean fact labels and values given to the impact assessment, by
// their text codes (the stored facts keep the Korean the AI read).
var assessFactCodes = map[string]string{"조치": "incident-field.action", "범위": "incident-fact.scope", "대상": "incident-field.target",
	"감지": "incident-field.rule", "신호 수": "incident-fact.signals", "되돌릴 수 있음": "incident-fact.reversible", "내용": "incident-field.note",
	"지침의 중요 사항": "incident-fact.critical", "최근 1시간 자동 실행": "incident-fact.auto-runs",
	"앱": "guide-scope.app", "클러스터": "guide-scope.cluster", "예": "incident-fact.yes", "아니오": "incident-fact.no"}

// assessmentIn is the stored assessment with its web-made words in lang:
// fact labels (and the scope and yes/no values), the floor reason and the
// policy. An assessment stored before keeps its Korean policy.
func assessmentIn(lang string, raw json.RawMessage) any {
	var a map[string]any
	if json.Unmarshal(raw, &a) != nil {
		return raw
	}
	if facts, ok := a["facts"].([]any); ok {
		for _, f := range facts {
			row, ok := f.(map[string]any)
			if !ok {
				continue
			}
			label, _ := row["label"].(string)
			if c := assessFactCodes[label]; c != "" {
				row["label"] = text(lang, c, nil)
				if v, _ := row["value"].(string); (label == "범위" || label == "되돌릴 수 있음") && assessFactCodes[v] != "" {
					row["value"] = text(lang, assessFactCodes[v], nil)
				}
			}
		}
	}
	if fl, ok := a["floor"].(map[string]any); ok {
		if r, _ := fl["reason"].(string); strings.HasPrefix(r, "incident-assess.") {
			fl["reason"] = text(lang, r, nil)
		}
	}
	if raw, ok := a["policyText"]; ok {
		var ps []store.Phrase
		if b, err := json.Marshal(raw); err == nil && json.Unmarshal(b, &ps) == nil {
			words := make([]string, len(ps))
			for i, p := range ps {
				words[i] = render(lang, p)
			}
			a["policy"] = strings.Join(words, ", ")
		}
		delete(a, "policyText")
	}
	return a
}
