# 최근 로그인 (내 계정)

"내 계정" 화면의 최근 로그인 목록이다. 로그인한 사용자는 자기 기록만 읽는다. 다른 사람의 기록을 읽는 길은 없다. 코드는 [routes_me.go](../../../internal/web/server/routes_me.go)에 있다.

## 어디에 남나

로그인을 판단한 서버(sfcd)가 자기 기록을 남긴다. 기록은 Raft에 넣지 않고 그 서버의 `observations.db`에 둔다([loginlog](../../../internal/loginlog/loginlog.go)). 그래서 로그인 실패가 아무리 많아도 클러스터 상태가 커지지 않는다.

- 기록이 남는 경우: 그 서버가 서명한 로그인 표(ticket)로 들어온 로그인만 남긴다. 성공과 실패가 모두 남는다. 없는 사용자 이름이나 위조된 표로는 남의 기록을 늘릴 수 없다.
- 실패 묶기: 같은 출처, 같은 방식, 같은 자격 증명, 같은 이유로 60초 안에 다시 실패하면 한 줄로 묶고 `count`만 올린다.
- 보관: 계정마다 서버당 최근 64줄, 최대 30일.
- 남기지 않는 것: 비밀번호, 토큰, 서명, 세션 키는 남기지 않는다.

읽을 때는 답하는 서버가 다른 멤버 서버의 기록을 SFCP로 받아 최신순으로 합친다. 답하지 않은 서버는 `missing`에 이름이 나온다. 그 서버의 기록은 그 페이지에 빠져 있을 수 있다.

## `GET /me/logins?after=`

```json
{"items":[
  {"at":"2026-11-27T08:01:02.345Z","count":1,"ok":true,"method":"password","credential":"password",
   "session":"s3f1e…","expiresAt":"2026-11-27T09:01:02Z",
   "client":"Mozilla/5.0 …","address":"203.0.113.5","source":"unix-uid:0","node":"jay2"},
  {"at":"2026-11-27T07:59:40.001Z","lastAt":"2026-11-27T08:00:31.900Z","count":7,"ok":false,
   "reason":"throttled","method":"password","credential":"password",
   "address":"203.0.113.5","source":"unix-uid:0","node":"jay2"}],
 "next":"1795766380001/jay2/9f…","missing":[],
 "budgetLeft":4,"budgetMax":5}
```

| 칸 | 뜻 |
|---|---|
| `at`, `lastAt` | 첫 시도 시각. 묶인 실패면 `lastAt`이 마지막 시도 시각이다 |
| `count` | 묶인 시도 수. 성공은 늘 1 |
| `ok`, `reason` | 성공 여부. 실패 이유는 `denied`(틀림·거절) 또는 `throttled`(시도 한도 초과) |
| `method`, `credential` | `password`·`token`·`private-key`, 그리고 쓴 자격 증명 ID |
| `session`, `expiresAt` | 성공으로 열린 세션의 ID와 만료 시각 |
| `client`, `address` | 브라우저가 보낸 user agent와 브라우저 주소. 웹이 알려 준 값이라 참고용이다. CLI 로그인처럼 웹이 알려 주지 않았으면 `address`는 `source`와 같다 |
| `source` | sfcd가 본 연결. 소켓으로 붙은 웹·CLI는 `unix-uid:N`, QUIC으로 붙은 클라이언트는 그 주소 |
| `node` | 판단한 서버 |
| `next` | 다음 페이지의 `after`. 한 페이지는 50줄 |
| `missing` | 기록을 읽지 못한 서버 |
| `budgetLeft`, `budgetMax` | 답한 서버(리더)가 이 사용자 이름으로 지금 더 받아 주는 비밀번호·토큰 시도 수. 서버마다 따로 세고, 12초마다 하나씩 다시 찬다. 자격 증명 저장소가 없는 서버면 없다 |

브라우저 주소는 연결 주소를 쓴다. 믿는 ingress(`trusted_proxies`)에서 온 요청이면 `X-Forwarded-For`의 마지막 칸을 쓴다.
