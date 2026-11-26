# mydc user: 사용자 계정

계정과 로그인 수단(키·비밀번호·일회용 토큰)을 다룬다. `revoke-session`을 뺀 명령은 시스템 관리자만 한다. 자기 로그인과 키는 `mydc login`이 다룬다.

| 명령 | 하는 일 |
|---|---|
| `mydc user list` | 계정 목록 |
| `mydc user show USER` | 계정과 로그인 수단(비밀 값은 서버에 없다) |
| `mydc user create USER [--public-key HEX] [--key-name key] [--admin] [--automation]` | 계정을 만든다 |
| `mydc user key add USER KEY --public-key HEX [--operations a,b]` | 로그인 키를 더한다 |
| `mydc user key disable USER KEY` | 로그인 키를 끈다 |
| `mydc user issue-password USER --profile PROFILE [--node NODE]` | 비밀번호를 정한다 |
| `mydc user issue-token USER --profile PROFILE --out FILE [--node NODE]` | 일회용 로그인 토큰을 새 파일에 쓴다 |
| `mydc user revoke-session USER SESSION` | 세션 하나를 끝낸다 |
| `mydc user scope USER [--operations a,b] [--key-only] \| --clear` | 계정 범위: 계정이 서명할 수 있는 action과 키 전용 로그인 |

- `--public-key`가 없으면 계정은 아직 로그인할 수단이 없다. 시스템 관리자(`--admin`)는 처음부터 키가 있어야 한다. `--automation` 계정은 키만 쓴다.
- 키를 더하거나 끄면 그 계정의 세션이 모두 끝나 다시 로그인해야 한다.
- `--operations`는 그 키로 할 수 있는 서버 action을 줄인다. 역할 권한은 그대로 적용된다.
- `user scope`는 계정 전체의 범위다(`set-account-scope`). 계정의 범위와 키의 `--operations`가 모두 맞아야 action이 된다. `--key-only`는 `--automation`과 같은 표시로, 켜진 비밀번호·토큰이 있으면 거부된다. 시스템 관리자에게는 범위를 줄 수 없다. 바꾸면 그 계정의 세션이 모두 끝난다.

## 비밀번호와 토큰

비밀번호는 터미널에서 두 번 묻는다. 터미널이 아니면 표준 입력의 첫 줄을 읽는다. 인자나 파일로 받지 않는다. 토큰은 `--out`의 새 파일(0600)에만 쓰고 화면에 내지 않는다. 이미 있는 파일에는 쓰지 않는다.

`--profile`은 서버에 설치된 credential provider 설정 이름이고 `--node`는 그 provider가 있는 서버다(기본: 지금 연결한 서버). 끊기면 `mydc op resume ID`가 저장한 요청을 이어 간다. provider에 이미 보낸 요청은 결과만 다시 묻고, 비밀번호를 아직 보내지 못했으면 명령을 처음부터 다시 실행해야 한다. 이어 가는 중에 받은 토큰은 파일로 넘겨줄 수 없으니 새로 발급한다.

## 아직 없는 것

`user sessions`(세션 목록)는 서버에 세션 목록 조회가 없어 아직 없다. `revoke-session`의 SESSION은 끝낼 세션의 ID다.
