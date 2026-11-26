## 도움말과 옵션 위치

유한 User RPC는 client 요청 EOF 뒤 server 응답을 받는다. 빠른 거부도 같은 순서이며 transport가 이 EOF를 확인하기 전 관리 효과를 수행하지 않는다. EOF 실패/전송 불명은 원 결과 조회·명시 재개로 정산하고 새 ID로 우회하지 않는다. 대용량 입력의 continue/body/EOF는 [Unix API](../../reference/unix-sockets.md)의 별도 순서를 따른다.

`mydc --help`는 로컬 프로필/wallet·사용자 계정·클러스터/tenant 운영·설치 신원 명령을 구분해 안내한다. 전역 옵션은 명령 앞에, 해당 명령의 옵션은 뒤에 둔다. 도움말은 설정 파일·wallet·로그인·서버 연결 없이 읽을 수 있다.

```sh
mydc --help
mydc login --help
mydc node --help
mydc node storage --help
mydc tenant --help
mydc app --help
mydc --context production --tenant payments --user alice app list
```

`context`, `wallet`, 계정·운영 명령군은 `--help`/`-h`로 세부 문법을 안내한다. `identity/version`과 설치 신원 명령의 사용법은 최상위 도움말과 [Quick-start 명령별 사용법](../../quick.md#5-명령별-세부-사용법)을 참조한다. node 구성 변경은 system admin 작업이며 `node shell`은 별도 사용자 scope/노드 grant를 사용한다. 접속할 곳과 기본 tenant는 로컬 [context](../../cli/context.md)이고, 원격 tenant 생성/삭제는 별도 `manage apply` 작업이다.

