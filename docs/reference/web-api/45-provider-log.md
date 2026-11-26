# 공급자 진단 로그 (UI-C1, 시스템 관리자)

외부 DNS 공급자(Hostinger 등)와 인증 기관(Let's Encrypt 등)을 부른 기록이다. 실제 클러스터에서 생긴 문제를 그 기록만으로 진단하려고 둔다. 코드는 [provlog](../../../internal/web/provlog)와 [diag_provider_log.go](../../../internal/web/server/diag_provider_log.go)에 있다.

- **기본은 꺼짐.** 웹 앱이 시작할 때마다 꺼진 상태로 시작한다. 꺼져 있는 동안은 아무것도 모으지 않는다.
- 시스템 관리자가 웹 앱 설정에서 켜면 모으기 시작하고, 디버깅 도구가 쓸 **임시 bearer 토큰**을 한 번 보여 준다. 웹은 토큰의 해시만 메모리에 둔다.
- **1시간 동안 활동이 없으면 저절로 꺼진다.** 활동은 토큰으로 읽은 요청과 새로 쌓인 항목이다. 활동이 계속 있어도 켠 지 24시간이 지나면 꺼진다. 꺼지면 토큰도 쓸 수 없다. 다시 켜면 새 토큰이 나오고 24시간도 새로 센다.
- 항목마다 HTTP 요청 하나의 요약이 들어 있다: method, URL, 상태 코드, 걸린 시간, 요청·응답 본문 앞부분(4KB), 몇 가지 응답 헤더(`Retry-After`, `RateLimit-*`, `X-Correlation-Id` 등). `Authorization`·쿠키는 남기지 않는다. bearer 토큰과 비공개 키, 이름에 `token`·`secret`·`passw`·`api_key`(`api-key`)·`private_key`·`hmac`·`credential`이 든 JSON 필드와 form 필드의 값, 비밀처럼 보이는 URL 질의 값은 가린다.
- 항목은 메모리(최근 5000개)와 데이터 폴더의 `logs/providers.jsonl`(8MB마다 하나를 `.1`로 돌림)에 남는다. 꺼진 뒤에도 시스템 관리자는 읽고 내려받을 수 있다.

## 끝점

| 끝점 | 누가 | 내용 |
|---|---|---|
| `GET /api/v1/diag/provider-log/state` | 관리자 세션 | 상태 |
| `POST /api/v1/diag/provider-log/enable` | 관리자 세션 | 켜기 → `{token, state}`. 켜진 동안 다시 부르면 토큰을 바꾼다 |
| `POST /api/v1/diag/provider-log/disable` | 관리자 세션 | 끄기 → 상태 |
| `GET /api/v1/diag/provider-log` | 관리자 세션 또는 토큰 | 폴링 조회 |
| `GET /api/v1/diag/provider-log/stream` | 관리자 세션 또는 토큰 | SSE |
| `GET /api/v1/diag/provider-log/download` | 관리자 세션 또는 토큰 | JSON lines 파일 (`application/x-ndjson`) |

토큰은 `Authorization: Bearer <토큰>`으로 보낸다. 틀리거나 만료된 토큰은 `401 token-expired`다. 관리자가 아닌 세션은 `403 denied`.

상태(State): `{enabled, enabledAt?, enabledBy?, lastActivity?, expiresAt?, disabledReason?, disabledAt?, entries, last}`. `disabledReason`은 `user`(끔), `idle`(1시간 무활동), `limit`(켠 지 24시간), `restart`(웹 앱 시작). `expiresAt`은 둘 중 먼저 오는 꺼질 시각이다. `entries`는 메모리에 있는 항목 수, `last`는 가장 새 seq다.

항목(Entry): `{seq, at, provider, conn?, op?, level, msg?, kind?, error?, attrs?, http?}`. `provider`는 `dns:<벤더>`, `acme:<인증 기관 ID>`, 켜고 끈 기록은 `mydc-web`. `level`은 `info`·`warn`(4xx)·`error`(5xx, 429, 연결 실패). `kind`는 공급자 오류 분류(`auth-failed`, `rate-limited` 등). `http`는 `{method, url, status?, durationMs, request?, response?, reqBytes?, respBytes?, headers?}`.

### 폴링

`GET /api/v1/diag/provider-log?after=<seq>&limit=<n>` → `{page: {entries, next, last, oldest, more}, state}`. 항목은 오래된 것부터 온다. 다음 쪽은 `after=<page.next>`. `limit`은 기본 500, 최대 5000. `tail=<n>`을 주면 가장 새 n개다.

거르기(폴링·SSE·내려받기 공통): `provider=`(같은 값, 또는 `dns:`처럼 `:`로 끝나는 앞부분), `conn=`, `op=`, `level=`(이 수준 이상), `since=`(RFC 3339), `q=`(항목 JSON에 든 글자).

### SSE

`GET /api/v1/diag/provider-log/stream?after=<seq>` (또는 `Last-Event-ID`). 먼저 `state` 사건 하나, 그다음 `after` 뒤의 항목을 `entry` 사건(`id`는 seq)으로 보내고 새 항목을 이어 보낸다. 20초마다 `: ping` 줄을 보낸다. 토큰으로 연 흐름은 기록이 꺼지면 `expired` 사건을 보내고 끝난다. 끊기면 마지막 seq로 다시 열면 빠짐없이 이어진다.

## 디버깅 도구

`mydc-web provider-log`가 위 끝점을 읽는다. 웹 컨테이너 안에서도 돌릴 수 있다.

```sh
export MYDC_WEB_DIAG_TOKEN=mpl_...          # 켤 때 보인 토큰
mydc-web provider-log -url https://web.example -tail 200 -format text
mydc-web provider-log -url https://web.example -format summary -provider dns:
mydc-web provider-log -url https://web.example -follow -out provider-log.jsonl
docker exec mydc-web mydc-web provider-log -tail 500 > provider-log.jsonl
```

- `-format jsonl`(기본, 항목 그대로), `text`(한 줄씩, 실패한 응답 본문 포함), `summary`(공급자·작업별 호출 수, 상태 코드, 평균 시간, 최근 경고·오류 20개).
- `-follow`는 SSE로 새 항목을 계속 받고, 끊기면 마지막 seq부터 다시 붙는다. 기록이 꺼지면 끝난다.
- 거르기: `-provider`, `-op`, `-level`, `-since 2h`, `-q`. 시작 위치: `-after <seq>` 또는 `-tail <n>`.
- 토큰: `-token-file` 또는 `MYDC_WEB_DIAG_TOKEN`(`-token`도 되지만 셸 기록에 남는다). 자체 서명 인증서면 `-insecure`.
