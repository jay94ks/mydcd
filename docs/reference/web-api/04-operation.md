## 작업(operation)

모든 관리 변경은 `submit`의 typed `Change`다. 브라우저가 opId(UUID v4, 소문자)를 만든다.

`POST /ops`

```json
{"opId":"6f1c...","action":"create-tenant","principal":"<user id>","expected":1,"payload":{...},"rootRevision":3,"tenant":"shop","target":"표시용","batch":"<UUID v4>"}
```

`principal`을 비우면 로그인한 사용자다. `sfcli manage apply`가 받는 동작이면 payload를 변경 파일처럼 읽어 sfcd가 받는 꼴(칸 순서까지)로 다시 쓰고, 맞지 않으면 `400 bad-payload`로 보내지 않는다. `batch`는 한 묶음으로 보낸 변경을 묶는 표시용 ID다([관리 변경](46-management-change.md)).

순서: 서명(Prepare) → **bbolt에 원 operation 저장** → 전송(Submit). 저장하지 못하면 보내지 않는다. `rootRevision`이 0이거나 없으면 데몬이 보내기 직전 `whoami`에서 그 action의 command key root(앱·Vault·볼륨·빌드·저장소 정비 등은 각자의 root, 원장은 LedgerRootRevision)로 채운다(CLI의 userauth Prepare와 같음). 대상 자원은 `expected`가 계속 지킨다.

```json
{"op":{"id":"6f1c...","requestId":"...","action":"create-tenant","tenant":"shop","target":"...","state":"applied","errorCode":"","resultFound":true,"resultCode":0,"index":5,"revision":6,"submittedAt":"...","updatedAt":"..."}}
```

| state | 뜻 | HTTP |
|---|---|---|
| `applied` | Result.Code 0 | 200 |
| `failed` | 전달됐고 Result.Code ≠ 0 (`resultCode`: 1 CAS 실패, 2 Invalid, 3 요청 충돌, 4 Forbidden, 5 Expired, 6 LedgerFull) | 200 |
| `rejected` | sfcd가 실행 전에 거부(`errorCode`: denied/invalid/unsupported/expired/ledger-full/not-session-issuer) 또는 보내기 전 로컬 실패 | 200 |
| `unknown` | 결과 불명(`errorCode`: unknown/not-leader/unavailable/closed/disconnected). 원 operation을 보존한다 | 202 |

- 같은 사용자가 같은 opId·같은 내용을 다시 보내면 **재전송하지 않고** 저장된 op를 돌려준다. 다른 내용이면 409 `op-conflict`.
- `unknown`에는 새 opId 재제출 버튼을 두지 않는다. 아래 두 끝점만 쓴다.

| 끝점 | 뜻 |
|---|---|
| `GET /ops?state=&limit=&children=1&batch=` | 내 작업 기록(최신순). state 생략 시 전체. `batch`를 주면 그 묶음만. 배포 묶음의 단계 행(`parent`가 있는 행)은 `children=1`일 때만 |
| `GET /ops/{id}` | 하나 |
| `POST /ops/{id}/result` | 저장한 원 operation 그대로 `result`. 못 찾으면 `unknown` 유지(미실행 증거 아님) |
| `POST /ops/{id}/resume` | 같은 원 operation을 현재 세션 권한으로 `resume`. 확정된 작업은 409 `settled`. 거부돼도 원 상태는 바뀌지 않는다 |
| `GET /ops/{id}/reason` | 그 op의 서명 원본 안에 든 사유 `{found, reason?, incident?, approvedBy?}`. 웹이 저장한 원본에서 읽는다(sfcd에 따로 읽는 method 없음). 배포 같은 묶음 op는 409 `job` |
| `GET /ops/{id}/revert`, `POST /ops/{id}/revert` | 확정된 변경을 바꾸기 전 값으로 되돌리기([변경 되돌리기](52-ops-revert.md)). op 보기의 `revert`(`here`/`link`/`no`)가 메뉴를 켤지 알려 주고, 되돌린 op에는 `revertOf`가 붙는다 |

작업 사유(REQ-9 mock, 표시용): `POST /ops`와 `{opId}`를 받는 모든 변경 끝점은 머리글 `X-SFC-Reason`(예 `autofix`)·`X-SFC-Incident`(장애 ID)를 받는다. 값은 UTF-8을 퍼센트 인코딩한 한 줄, 각 256자 이하다(아니면 400). 사유는 op digest에 들어가므로 같은 opId에 다른 사유는 409 `op-conflict`이고, 서명 원본과 함께 sfcd에 가며 op 보기의 `reason`에도 나온다. 권한 판단에는 쓰지 않는다. 배포 묶음(`/apps/deploy`)과 빌드 zip 조각은 아직 사유를 싣지 않는다.

확정된(`applied`/`failed`/`rejected`) 행은 기본 30일 뒤 지운다. `unknown`은 확정될 때까지 지우지 않는다.

