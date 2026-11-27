# CLI 신원·접속

`sfcli`는 현재 Linux user의 `~/.sfc`(0700)에 자기 파일을 둔다. 어느 것도 서버 권한을 주지 않는다. 서버는 모든 요청을 그때의 로그인과 권한으로 다시 확인한다.

```text
~/.sfc/
  config.yaml              context: 어디에, 누구로, 어느 tenant에
  trust/<cluster>.yaml     확인한 노드 공개키
  wallet.bin               이름 있는 개인키와 login 자격(암호화)
  sessions/<cluster>/      로그인 session과 보낸 작업의 원본
  ops/                     sfcli op 목록
```

```sh
sfcli context add production sfcp://control.example:7443 --user alice --tenant payments
sfcli --cluster production login --user alice --method private-key --key operator
sfcli whoami
```

context 추가는 노드 공개키 확인이 필요하고(`-y`로 건너뛸 수 없다), Unix 접속에도 같은 사용자 인증·권한을 적용한다. 로그인 기록과 작업 journal은 클러스터 ID로 나뉘므로 context 이름이나 주소를 바꿔도 이어서 쓴다. 사용법은 [context](../cli/context.md)에 있다.

wallet은 이름 있는 개인키와 login 자격을 보관한다. 패스워드에서 Argon2id로 암호 키를 유도하고 저장마다 무작위 IV를 사용한다. 계정 자격은 서로 공존하며 현재 대상에 후보가 여러 개면 `--user NAME`을 요구한다. 최근 login 계정을 임의 선택하지 않는다.

socket의 wire는 [Unix API](../reference/unix-sockets.md), 명령과 파일 형식의 설계는 CLI 명령과 파일 형식을 따른다. 한 사용자에게 등록한 여러 개인키의 선택과 같은 username의 현재 wallet session, 계정 revision 변경 시 회수 범위는 [사용자 자격](security.md#사용자당-여러-인증-키)을 따른다.
