# 초대 링크

관리자가 새 계정(또는 키를 잃은 계정)에 한 번만 쓰는 초대 링크를 만들고, 받은 사람이 그 링크로 자기 키를 등록한다. 코드는 [invites.go](../../../internal/web/server/invites.go)와 [sfc/invite.go](../../../internal/web/sfc/invite.go)에 있다.

초대는 계정에 붙는 일회용 토큰 자격 증명이다. sfcd 쪽 규칙은 [초기 자격 증명](../initial-credentials.md)을 따른다.
- 자격 증명 ID는 `invite-<만료 Unix 초>-<8자리 hex>`다. 사용자 목록은 이 ID에서 만료 시각을 읽는다.
- 한 계정에 켜진 초대는 하나뿐이다. 새로 만들려면 앞의 것을 먼저 꺼야 한다(`revoke`).
- 코드는 발급 답 한 번에만 링크로 나온다. 웹은 코드를 bbolt, 로그, 같은 opId 재요청 답 어디에도 두지 않는다.
- 받은 사람의 개인 키는 브라우저 밖으로 나가지 않는다. 웹은 공개 키와 증명 서명만 받는다.

## 관리자

### `POST /users/{u}/invites`

시스템 관리자만 쓴다. `{u}`는 사용자 이름이다.

```json
{"opId":"…","expires":"24h"}
```

`expires`는 `1h`, `24h`, `7d` 가운데 하나다. sfcd가 토큰을 만들고(`initial-credential-stage`), 웹이 `issue-initial-credential`을 보낸다.

```json
{"op":{…,"state":"applied"},
 "link":"/login/invite?u=carol#Xk3…","expiresAt":"2026-11-28T08:00:00Z"}
```

- `link`와 `expiresAt`은 이 요청이 변경을 보냈고 `applied`일 때만 있다. 같은 opId로 다시 보내면 `op`만 온다. 링크를 잃었으면 `revoke` 뒤 새로 만든다.
- 이미 켜진 초대(또는 다른 일회용 토큰)가 있으면 `op.state`가 `failed`다.
- 키를 잃은 활성 사용자의 복구도 같은 엔드포인트를 쓴다. 켜진 초대가 없을 때만 된다.

### `POST /users/{u}/invites/revoke`

```json
{"opId":"…","expected":12}
```

켜진 초대를 끈다(`disable-credential`). `expected`는 그 계정의 `accountRevision`이다. 켜진 초대가 없으면 `409 no-invite`다. 초대만 있던 새 계정은 끈 뒤 켜진 로그인 방법이 하나도 없게 된다. 일반 계정은 그래도 되고, 시스템 관리자 계정은 하나는 남아야 한다.

### `GET /users`의 `invite`

각 줄에 켜진 초대가 있으면 붙는다.

```json
{"username":"carol", …, "invite":{"state":"active","expiresAt":"2026-11-28T08:00:00Z"}}
```

`state`는 `active` 또는 `expired`다. sfcd는 이미 연 초대와 열지 않은 초대를 가르지 않는다. 받은 사람이 키를 등록하고 초대를 끄기 전까지는 연 초대도 `active`로 보인다.

## 받은 사람 (로그인 없음)

순서가 중요하다. `open`이 코드를 소비하므로 프런트엔드는 키 생성과 암호 문구 확인을 `open`보다 먼저 끝낸다. 그래야 `open` 뒤에 할 일이 서명 한 번뿐이고, 받은 사람이 도중에 멈춰도 코드를 헛되이 쓰지 않는다.

1. 링크의 `u`와 `#` 뒤 코드를 읽는다. 코드는 URL 조각이라 서버 로그에 남지 않는다.
2. 키를 만들고 암호 문구를 두 번 받아 확인한다(브라우저 안에서).
3. `POST /login/invite/open`
4. 3의 답으로 증명을 서명하고 `POST /login/invite/finish`
5. 새 키로 보통 키 로그인(`/auth/key/challenge` → `login` → `approve`)
6. 로그인한 세션으로 쓴 초대를 끈다(`disable-credential`, 자기 일회용 토큰은 스스로 끌 수 있다).

### `POST /login/invite/open`

```json
{"username":"carol","code":"Xk3…"}
```

코드로 토큰 로그인을 하고(코드는 여기서 소비된다) 그 세션을 웹이 10분 동안 들고 있는다.

```json
{"ticket":"…","userId":"u-carol","username":"carol","accountRevision":12,
 "clusterId":"<hex 32바이트>","expiresAt":"2026-11-27T08:10:00Z"}
```

`expiresAt`은 이 세션(`ticket`)이 끝나는 때다. 초대가 아닌 토큰은 이 엔드포인트에서 쓰지 않는다.

### `POST /login/invite/finish`

```json
{"ticket":"…","credential":{"id":"web-1","publicKey":"<hex 32바이트>"},"label":"노트북",
 "challenge":"<hex 32바이트, 브라우저가 고른 난수>","proof":"<base64 64바이트>"}
```

`proof`는 새 키로 `access.CredentialAdditionBytes(clusterId, accountRevision, 추가 내용)`에 한 서명이다. 추가 내용은 사용자 ID, `credential.id`, 방법 `private-key`, `label`, 공개 키, `challenge`다. 바이트 모양은 [클라이언트 인증](../client-authentication.md)에 있다. `credential.id`는 `invite-`로 시작할 수 없다.

웹은 토큰 세션으로 본인 `add-credential`을 보내고 세션을 닫는다. 답은 `{"credential":"web-1","username":"carol"}`다. sfcd가 받지 않으면(`409 not-applied`) 초대를 다시 받아야 한다.

## 오류

| 코드 | 뜻 |
| --- | --- |
| `410 invite-invalid` | 링크가 이미 쓰였거나, 만료됐거나, 꺼졌거나, 없다. sfcd가 가르지 않으므로 하나로 합쳤다. |
| `410 ticket-expired` | `open`한 뒤 10분이 지났거나 `finish`를 이미 했다. |
| `409 no-invite` | `revoke`할 켜진 초대가 없다. |
| `400 bad-request` | `expires`, 키, 증명 모양이 틀렸다. |
