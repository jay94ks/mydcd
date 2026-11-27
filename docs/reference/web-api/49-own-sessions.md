# 열린 세션 (내 계정)

"내 계정" 화면의 열린 세션 목록과 끊기다. 로그인한 사용자는 자기 세션만 보고 끊는다. 코드는 [routes_me.go](../../../internal/web/server/routes_me.go)에 있다.

sfcd는 세션 목록을 따로 두지 않는다. 각 서버의 [최근 로그인](48-own-logins.md) 기록 가운데 성공한 것을 골라 목록을 만든다. 다음 세션은 목록에서 뺀다.
- 만료된 세션
- 끊은(`revoke-session`) 세션
- 계정이 바뀐 뒤(account revision이 다르면)의 세션
- 쓴 자격 증명이 꺼진 세션

세션은 길어야 1시간이다. 답하지 않은 서버는 `missing`에 나오고, 그 서버가 연 세션은 목록에 빠져 있을 수 있다.

## `GET /me/sessions`

```json
{"items":[
  {"id":"s3f1e…","current":true,"method":"password","credential":"password",
   "at":"2026-11-27T08:01:02.345Z","expiresAt":"2026-11-27T09:01:02Z",
   "client":"Mozilla/5.0 …","address":"203.0.113.5","source":"unix-uid:0","node":"jay2"}],
 "missing":[]}
```

`current`는 지금 이 브라우저가 쓰는 세션이다. 나머지 칸은 [최근 로그인](48-own-logins.md)과 같다(`at`은 로그인 시각).

## `DELETE /me/sessions/{id}`

```json
{"opId":"…"}
```

그 세션을 끊는다(`revoke-session`). 결과는 다른 변경과 같은 작업(op) 응답이다([작업](04-operation.md)). 지금 세션은 여기서 끊지 않고 `422`로 돌려보낸다. 지금 세션은 로그아웃으로 끝낸다.

"다른 세션 모두 끊기"는 따로 없다. `current`가 아닌 행마다 이 요청을 보낸다. 세션은 몇 개 되지 않는다.
