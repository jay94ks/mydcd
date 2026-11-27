# key·login: 키와 로그인

```sh
sfcli key import admin /etc/sfc/admin-identity/key.pem
sfcli context add lab --user admin --wallet-key admin
sfcli enroll admin --key admin       # 새 클러스터의 첫 관리자, 한 번만
sfcli login
sfcli whoami
sfcli logout
sfcli version
```

## key

개인키는 `~/.sfc/wallet.bin`에 wallet 비밀번호로 암호화해 둔다. 개인키와 비밀번호는 출력하지 않는다.

| 명령 | 하는 일 |
|---|---|
| `key list` | 키 이름과 공개키(hex) |
| `key create NAME` | 새 키를 만든다 |
| `key import NAME FILE` | PKCS#8 Ed25519 PEM 개인키를 넣는다 |
| `key show NAME` | 공개키 |
| `key passwd` | wallet 비밀번호를 바꾼다(터미널에서만) |

- 첫 `create`나 `import`가 wallet을 만들며 새 비밀번호를 두 번 묻는다.
- 저장이 중간에 끊긴 wallet은 다음 key 명령이 먼저 마무리한다.
- 스크립트는 `SFC_WALLET_PASSWORD_FILE`에 비밀번호 파일 경로를 준다. 0600 일반 파일이어야 하고 끝 줄바꿈 하나는 뺀다. 모든 명령의 wallet 비밀번호 질문이 이 파일을 쓴다.

## login·logout·whoami

| 명령 | 하는 일 |
|---|---|
| `login [USER]` | 로그인하고 session을 wallet에 둔다. USER는 생략하면 `--user`, 그다음 context의 user |
| `logout` | session을 끝낸다. 앞선 logout의 답을 못 받았으면 같은 요청을 다시 보내 마무리한다(새 요청을 만들지 않는다) |
| `whoami` | 로그인한 사용자, system admin 여부, 쓸 수 있는 tenant, 만료 시각 |

login 옵션:

- 기본은 wallet 키 로그인이다. 키는 `--key NAME`, 생략하면 context의 wallet 키.
- `--password`·`--token`: 비밀번호나 토큰으로 로그인한다. 터미널에서 묻고, `--stdin`이면 표준 입력에서 한 줄 읽는다. 저장하지 않는다.
- `--credential ID`: 같은 종류의 자격이 여러 개일 때 고른다.
- `--approve-with KEY`: 비밀번호·토큰 session을 등록된 wallet 키로 함께 승인한다. 독립 승인을 요구하는 클러스터의 관리 명령에 필요하다. 권한 범위는 넓어지지 않는다.

한 클러스터에 여러 계정으로 로그인해 둘 수 있다. 그때는 명령마다 `--user`로 고른다. 최근 로그인한 계정을 저절로 고르지 않는다.

## enroll

`sfcli enroll USER --key KEY [--user-id ID]`는 `sfcd init --admin-public-key`로 만든 빈 클러스터에 첫 system admin을 등록한다. KEY는 그 공개키에 맞는 wallet 키다. 요청 ID는 `enroll-<user-id>`로 정해지므로 다시 실행하면 같은 요청의 결과를 확인한다. user-id는 생략하면 USER와 같다.

## version

CLI 버전과, 현재 context가 있으면 그 서버의 버전·프로토콜. 로그인이 필요 없다.

버전은 `major.minor.build`(예: `0.1.3`)다. 릴리스가 아닌 개발 빌드는 `major.minor.0-dev`로 보인다. `sfcli --version`과 `sfcd version`은 한 줄로 `sfcd 0.1.3 (commit 1a2b3c4d5e6f)`처럼 출력한다. 빌드한 소스 트리에 커밋하지 않은 변경이 있었으면 `, modified`가 붙는다. 같은 major 안에서는 minor·build가 달라도 서로 호환된다.
