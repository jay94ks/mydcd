# 실행과 CLI 설정

빌드 실행 worker는 managed workload 노드의 sfcd에 내장된다. CLI를 상시 켜 두지 않는다.
빌드 정책의 `WorkspaceBytes`는 입력 수락 예산, `CacheBytes`는 캐시 정리 목표다. MVP는 디스크 쓰기 강제 상한을 제공하지 않으며 ext4 project quota 준비를 요구하지 않는다. CPU·메모리·동시성·시간 제한과 등록 root 격리·원 자료 정산은 유지한다.
빌드 시작 시 서명해 고정한 source reader/run 참조는 원 job의 실제 종료 정산까지 유지한다.
CLI 재접속·취소가 원 source 승인 반환이나 다른 자격으로의 자동 교체를 뜻하지 않는다.
`sfcli build show/logs`로 원 빌드를 조회하며, 재접속으로 새 빌드를 자동으로 만들지
않는다. [현재 worker/private base 연결 범위](../reference/image-build-jobs/04-owner.md)를 참고한다.

이미지 빌드의 FROM 해결은 수락된 job의 native owner가 원 source reader를 통해 수행한다.
CLI 로그인 자격을 다른 노드로 복제하거나 별도 registry proxy 주소를 지정하지 않는다.
[job/base 메시지와 현재 연결 범위](../reference/image-build-jobs/04-owner.md)를 따르며
digest 해결과 실제 BuildKit private pull·빌드 성공을 구분한다.
FROM Bearer 교환은 원 builder와 source owner 사이의 보호된 SFCP와 BuildKit session에서
처리한다. CLI에 registry password/token을 복사하거나 Docker config를 준비할 필요가 없다. 같은 승인 external reader의 여러 FROM repository는 고정 pull scope 전부를 확인해 교환하며, 다른 reader의 자격을 합치지 않는다. Basic-only/managed 복수 scope와 실제 전체 빌드 검증의 현재 범위는 [job 명세](../reference/image-build-jobs/04-owner.md)를 따른다.
session·유한 native solve는 원 daemon/SDK 결과를 구분하며 같은 job 명세의 실제 CA/native 검증·Basic/복수 repository 잔여 범위를 따른다.

registry·이미지·빌드 명령(`sfcli registry`, `sfcli image`, `sfcli build`)은 [docs/cli](../cli/README.md)의 [registry](../cli/registry.md)·[image](../cli/image.md)·[build](../cli/build.md) 문서에 있다.

명령별 적용대상·권한·로컬 등록/원격 변경·원 결과/재개의 구분은 [명령어 적용대상표](../architecture/command-targets.md)를 따른다.

`manage tasks [--app NAME] [--node NODE] [--after CURSOR]`는 선택한 tenant의 Task를 조회한다. `--all-tenants`는 현재 읽기 권한이 있는 tenant 전체에 같은 필터를 적용한다. [Task 행·페이지 계약](../reference/task-observability.md)을 따른다.

`manage node-summary|node-disks|mesh-links [--node NODE] [--after CURSOR] [--system]`는 선택 tenant의 허용 범위를 조회하며 `--system`은 관리자 전체 조회를 명시한다. `node disks [NODE]`·`mesh links`는 같은 코어의 별칭이다. `manage node-tenant-usage --node NODE [--after CURSOR]`는 관리자용 tenant 사용량 페이지다. `raft-status [--after CURSOR]`는 로컬 마지막 적용 정책으로 인증하여 quorum 없이 진단만 반환한다. [노드 관측 API](../reference/node-observations.md)를 따른다.

`manage app-source --app NAME [--deployment ID] [--revision VERSION] [--section source|local-services|overlays] [--raw]`는 선택 tenant의 원문을 읽는다. `--raw`는 전체 분할 입력과 digest를 확인한 뒤 원 바이트만 출력한다. `manage app-revisions --app NAME [--deployment ID] [--after CURSOR]`는 보존 버전을 읽는다. [버전·권한·한도](../reference/app-source.md)를 따른다.

CLI의 Linux user별 wallet·프로필·대상 선택은 U0/D7 명세를 따른다. 로컬 관리 끝점의 접속 권한과 wire 규칙은 [Unix 소켓 API](../reference/unix-sockets.md)를 따른다.


제품은 `sfcli`·`sfcd` 두 Go 실행 파일이다. 자체 설정/프로토콜/저장 schema와 제품 표시는 1이다. 고정 toolchain의 `tools/go`를 사용한다. 빌드가 의존성을 자동으로 공급하지 않는다.

```sh
GOPROXY=off GOSUMDB=off tools/go build -p 2 -o build/ ./cmd/sfcli ./cmd/sfcd
build/sfc --help
build/sfcd --version
```

설치용 공개 신원은 `sfcli identity create DIR`로 생성한다. 개인키는 0600, 새 디렉터리는 0700이며 기존 신원을 덮어쓰지 않는다. node/client YAML의 신원 디렉터리는 이미 생성된 신원을 가리킨다. 설정의 공개키는 실제 생성 결과로 채운다. 노드 ID·키·클러스터·genesis 관리자·승인 peer manifest는 상태 root에 결합하며 같은 DB를 다른 신원으로 열지 않는다.

장수 SFCP client의 Unix 유휴 연결은 다음 요청 전 보수적인30초 캐시 기한으로 교체한다. 진행 중 요청이나 원 작업의 ID/서명은 변경하지 않는다. 임의 단절·전송 후 불명은 원 결과를 조회하며 새 연결을 이유로 자동 재제출하지 않는다. 자세한 수명 규칙은 [Unix API](../reference/unix-sockets/16-section.md)를 따른다.

## 절 목록

이 문서는 절마다 파일로 나뉘어 있다.

| 절 | 파일 |
|---|---|
| 도움말과 옵션 위치 | [cli/01-section.md](cli/01-section.md) |
| 접속할 곳(context) | [../cli/context.md](../cli/context.md) |
| 로그인 계정 선택 | [cli/05-section.md](cli/05-section.md) |
| 관리 명령·Compose 선언·접속 수단 | [cli/07-compose.md](cli/07-compose.md) |
| 관리 명령과 결과 | [cli/08-section.md](cli/08-section.md) |
| 기존 static root의 catalog 활성화 CLI | [cli/09-static-root-catalog-cli.md](cli/09-static-root-catalog-cli.md) |
| 사용자 로그인·tenant 선택 | [cli/10-tenant.md](cli/10-tenant.md) |
| 서명된 metadata 관리 CLI | [cli/11-metadata-cli.md](cli/11-metadata-cli.md) |
| init/join·runtime node | [cli/13-init-join-runtime-node.md](cli/13-init-join-runtime-node.md) |
| compose·login CLI | [cli/14-compose-login-cli.md](cli/14-compose-login-cli.md) |
| Managed 대상 가입 CLI | [cli/15-managed-cli.md](cli/15-managed-cli.md) |
| inline lifecycle source 준비 | [cli/19-inline-lifecycle-source.md](cli/19-inline-lifecycle-source.md) |
| 컨테이너 로그·프로세스·리소스 조회 | [cli/22-section.md](cli/22-section.md) |
| 컨테이너 로그 정리 | [cli/23-section.md](cli/23-section.md) |
| 본인 자격 조회와 관리 사유 | [cli/24-tenant.md](cli/24-tenant.md) |
| 교체 미리보기와 begin-app 대상 | [cli/25-cd.md](cli/25-cd.md) |
| tenant 허용 저장 경로 선택 | [cli/26-tenant.md](cli/26-tenant.md) |
| 서비스·Git 연결 검사 | [cli/27-git.md](cli/27-git.md) |
| 단독 컨테이너·관리 자원 조회 | [cli/28-volume.md](cli/28-volume.md) |
| 설치 키 교체 복구 | [cli/29-lifecycle.md](cli/29-lifecycle.md) |
