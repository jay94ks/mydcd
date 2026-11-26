# mydc 명령

`mydc`는 `mydc 자원 동사 [이름] [옵션]` 모양이다. 설계와 옮기는 순서는 CLI 명령과 파일 형식에 있다. 옮기는 동안 아직 옮기지 않은 그룹은 [옛 CLI 설명](../configuration/cli.md)을 따른다. 그룹을 옮길 때마다 이 목록에 그 그룹 문서를 더하고 옛 설명을 지운다.

| 그룹 | 문서 |
|---|---|
| `context` | [어디에, 누구로, 어느 작업 공간에](context.md) |
| `key`, `login`, `logout`, `whoami`, `enroll`, `version` | [키와 로그인](account.md) |
| `app` | [app.yaml로 앱 배포하고 돌보기](app.md) |
| `op` | [보낸 작업 확인·재개](op.md) |
| `node` | [서버](node.md) |
| `cluster` | [돌아가는 클러스터](cluster.md) |
| `events` | [진단 이벤트](events.md) |
| `tenant` | [작업 공간](tenant.md) |
| `user` | [사용자 계정](user.md) |
| `network` | [망과 network.yaml](network.md) |
| `route` | [작업 공간 사이 연결](route.md) |
| `volume` | [볼륨](volume.md) |
| `registry` | [내장 registry와 외부 이미지 출처](registry.md) |
| `image` | [registry 안의 이미지](image.md) |
| `build` | [이미지 빌드](build.md) |
| `secret` | [Secret과 그룹](secret.md) |
| `cd` | [Git 브랜치에서 앱 배포하기](cd.md) |
| `lifecycle` | [lifecycle 스크립트와 정책](lifecycle.md) |
| `ingress` | [앱의 외부 접속 보기와 제어](ingress.md) |
| `certificate` | [ingress TLS 인증서](certificate.md) |
| `domain` | [클러스터에 등록한 도메인](domain.md) |

## 모든 명령에 공통

- 옵션은 명령 단어 앞이나 뒤 어디에 써도 된다. `mydc op show 7f3a -o json`과 `mydc -o json op show 7f3a`는 같다.
- `--` 뒤의 단어는 옵션으로 읽지 않고 그대로 명령에 넘긴다.
- `mydc 명령 --help`는 그 명령의 쓰임, 하위 명령, 옵션을 보여 준다.
- AI 에이전트가 `mydc`를 쓸 때 읽을 안내는 [SKILL.md](../../cmd/mydc/SKILL.md)다. CLI 패키지가 `/usr/local/share/mydc/SKILL.md`(압축 파일이면 실행 파일 옆)에 설치하고, `mydc --help`가 그 위치를 알려 준다.
- `-o table|json|yaml`: 기본은 사람이 읽는 표다. 스크립트는 `-o json`을 쓴다. 표에 없는 값도 json·yaml에는 모두 나온다.
- 종료 코드: 0 성공, 1 실패, 2 잘못된 명령줄, 4 결과를 아직 모름(`mydc op show ID`로 확인). 그 밖의 코드는 명령 문서에 적는다.
- 비밀번호나 y/N 확인은 stdin이 터미널이고 명령이 그 터미널의 foreground에서 돌 때만 묻는다. 파이프·백그라운드·터미널 없는 실행에서는 묻지 않고 바로 실패한다. 환경 변수 `MYDC_NONINTERACTIVE=1`은 터미널이 있어도 묻지 않게 한다(스크립트·CI용, 플래그는 없다). 비밀번호는 `MYDC_WALLET_PASSWORD_FILE`([account](account.md)) 같은 파일이나 서술자로 준다.
- 크기는 `512`, `64KiB`, `10MiB`, `2GiB`처럼 쓴다(KB·MB·GB도 1024 배수로 읽는다).
