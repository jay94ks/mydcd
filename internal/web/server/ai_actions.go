// SPDX-License-Identifier: Apache-2.0

package server

import "github.com/jay94ks/seafield/internal/web/sfc"

// webAction is what the web knows about one change the AI may lead to:
// the rule floor of its impact and how it is undone. Coordinator change
// tools and incident temporary actions both point here, so one change has
// one grade (R19). sfcd still judges permission; this is screen and AI
// shaping only.
type webAction struct {
	Impact     string // low / medium / high
	Reversible bool
	Revert     string // the card's "how to undo"
	Confirm    string // irreversible: the argument the person types again
}

// webActions is keyed by the sfcd action, or, for an incident action made
// of several calls, by that action's own ID.
var webActions = map[string]webAction{
	sfc.ActionCordonNode:        {Impact: impactLow, Reversible: true, Revert: "node_uncordon으로 다시 배치를 허용해요."},
	sfc.ActionUncordonNode:      {Impact: impactLow, Reversible: true, Revert: "node_cordon으로 다시 막을 수 있어요."},
	sfc.ActionPruneNodeImages:   {Impact: impactMedium, Revert: "지운 이미지는 되돌릴 수 없어요. 필요할 때 저장소에서 다시 받아요.", Confirm: "node"},
	sfc.ActionDrainNode:         {Impact: impactHigh, Reversible: true, Revert: "옮긴 작업은 자동으로 돌아오지 않아요. 필요하면 다시 배치해요."},
	sfc.ActionRestartTask:       {Impact: impactLow, Reversible: true, Revert: "다시 시작은 되돌릴 수 없지만 상태는 그대로예요."},
	sfc.ActionSyncApp:           {Impact: impactMedium, Reversible: true, Revert: "이전 버전으로 되돌리기(recover)로 돌아가요."},
	sfc.ActionPauseAppCD:        {Impact: impactLow, Reversible: true, Revert: "app_cd_resume으로 다시 켜요."},
	sfc.ActionResumeAppCD:       {Impact: impactMedium, Reversible: true, Revert: "app_cd_pause로 다시 멈춰요."},
	sfc.ActionBeginVolumeBackup: {Impact: impactLow, Reversible: true, Revert: "만든 백업은 지울 수 있어요."},
	sfc.ActionReconnectTunnel:   {Impact: impactLow, Reversible: true},

	// incident actions of several calls
	"cd-rollback":       {Impact: impactLow, Reversible: true},
	"rollback-previous": {Impact: impactMedium, Reversible: true},
	"move-service":      {Impact: impactMedium, Reversible: true},
	"restart-registry":  {Impact: impactLow, Reversible: true},
}

// aiAllows is the one rule for changes the AI leads to (Jay 2026-11-27):
// a change a person approves counts as allowed, unless its impact is high;
// high is never proposed or run by the AI on any path.
func aiAllows(impact string) bool { return impact != impactHigh }
