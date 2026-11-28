## 공통 규칙

- JSON, UTF-8. 응답 필드 이름은 camelCase다. sfcd 타입의 필드는 첫 대문자 덩어리만 소문자로 바꾼다(`ID`→`id`, `CPUPercent`→`cpuPercent`, `NodeA`→`nodeA`). **map의 키는 바꾸지 않는다**(비밀값 키 이름 등 사용자 자료).
- 키·digest 같은 고정 길이 바이트(`[32]byte`)는 hex 문자열, 가변 바이트(`[]byte`)는 base64, 시각은 sfcd가 준 Unix 초 정수 그대로다. 웹이 만든 시각(`asOf`, `expiresAt`, 작업 기록 시각)은 RFC 3339 UTC다.
- 쿠키 `sfc_web_session`: HttpOnly, SameSite=Strict, Path=/, 기본 Secure. 값은 서버 세션 ID이며 DB에는 해시만 남는다.
- GET이 아닌 모든 `/api/` 요청은 헤더 `X-SFC-Web: 1`이 필요하다. 없거나 `Origin`이 다른 호스트면 403 `csrf`.
- 화면 파일: `/api/` 밖의 GET은 화면 빌드에서 찾고, 없으면 `index.html`을 준다(화면 경로를 새로고침해도 된다. `/system/domains/example.com`처럼 점이 들어 있어도 같다). `assets/` 아래에 없는 파일만 진짜 404다. `index.html`은 화면 언어를 `<html lang="ko|en">`에 넣어 준다. 순서: 쿠키 `sfc_lang_user`(로그인한 계정의 기본 언어, 화면이 적고 로그아웃 때 지움) → 쿠키 `sfc_lang`(이 브라우저의 언어) → `Accept-Language`(품질 순으로 처음 맞는 `ko*`·`en*`) → `en`. 응답에 `Content-Language`, `Vary: Accept-Language, Cookie`가 붙는다. 화면은 `document.documentElement.lang`을 처음 언어로 쓴다(CSP `script-src 'self'`라 인라인 값은 쓰지 않는다). 한국어가 아니면 그 언어 문구 묶음 `assets/lang-<언어>-<해시>.js`가 정확히 하나 있을 때 `<link rel="modulepreload">`를 `</head>` 앞에 넣는다.
- 보안 헤더: CSP `default-src 'self'; script-src 'self'; ...`(외부·inline script 금지), `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`. API 응답은 `Cache-Control: no-store`.
- 요청 본문은 알 수 없는 필드를 거부한다. 본문 최대 8 MiB(app.yaml 4 MiB).

### 목록

```json
{"items": [...], "next": "<cursor>", "revision": 9, "asOf": "2026-11-21T09:30:00Z"}
```

다음 페이지는 `?after=<next>`. 페이지 크기는 sfcd가 정한다. `revision`이 바뀐 페이지를 하나로 합치지 않는다(화면은 새로고침 안내).

### 오류

```json
{"error": {"code": "denied", "message": "...", "inputCode": "...", "leader": "..."}}
```

| HTTP | code | 뜻 |
|---|---|---|
| 400 | `bad-request`, `confirm-mismatch` | 입력 형식 오류 |
| 401 | `session-expired` | 세션 없음·만료, 또는 sfcd 연결/세션이 끝남(연결 끊김 포함). 다이얼로그로 다시 로그인 |
| 401 | `ticket-expired` | 로그인 ticket이 없거나 만료(한 번 쓰면 끝). 처음부터 다시 |
| 403 | `denied`, `not-session-issuer`, `csrf` | 권한·대상 거부. 다른 작업 공간의 '없음'과 '권한 없음'은 같은 `denied` |
| 404 | `not-found`, `missing` | |
| 409 | `op-conflict`, `settled`, `cursor-expired` | 같은 opId에 다른 내용, 이미 확정된 작업 재개, 이벤트 cursor 만료 |
| 410 | `expired` | sfcd 요청 보존 window 만료 |
| 422 | `invalid` | 계획/입력 부적합(`inputCode` 참조) |
| 501 | `unsupported` | sfcd에 없는 method(REQ 대기) |
| 503 | `unavailable`, `not-leader`, `disconnected` | 합의 불가·leader 아님·sfcd 연결 실패. 화면은 전체 띠 + 변경 잠금 |
| 504 | `timeout` | 30초 안에 응답 없음 |
| 507 | `ledger-full` | 내구 요청 기록 예산 거부 |

