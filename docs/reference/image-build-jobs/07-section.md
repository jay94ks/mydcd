## 노드 작업 공간과 출력의 수명

새 native job은 Create 전에 SDK 모드를 journal에 고정한다. 같은 digest 고정 rootless
이미지의 rootlesskit/buildkitd가 원 절대 deadline 안에서만 동작하며 daemon socket은 원
output 디렉터리 안의 `buildkit.sock`이다. host TCP 포트를 열거나 호스트 Docker socket을
빌더에 전달하지 않는다. SDK는 원 FD 아래의 Unix socket만 사용하고 source auth/Secret
provider·동일 source policy·보호된 context FS와 OCI directory exporter를 연결한다.
Info에서 고정 BuildKit v0.35.1을 확인한 뒤에만 solve를 보내며, 버전 확인 실패를
source-policy 미적용 실행으로 우회하지 않는다.
기존 CreateSent journal의 daemonless 모드를 현재 모드로 덮어쓰지 않는다.

optional native Solve는 `{Sent,Returned,Stopping,Code,Directory,TLS?,Trust?}`다. 안정적인 solve Ref는 원
Spec digest이며 Sent를 먼저 동기 저장한 뒤 SDK Solve를 한 번만 호출한다. 준비 단계의
Info/socket 확인만 재시도하고 응답 유실이나 node 재기동 뒤 Solve를 재제출하지 않는다.
Sent인데 원 결과가 없으면 같은 daemon의 확실한 종료로 로컬 효과를 정산하고 실패 처리한다.
출력 파일 존재·daemon exit 0을 SDK 성공으로 대신하지 않는다.

출력은 SDK의 긍정 결과와 실제 daemon 종료/Wait/Remove가 모두 있어야 읽을 수 있다.
성공 뒤 daemon Stop은 사용자 Cancel과 구분하며 SIGTERM 종료 코드가 SDK 결과를 지우지
않는다. 원 image directory inode·FD와 모든 SDK/Secret/auth/status/log I/O를 보유하고,
실제 join 뒤에만 원 작업 공간·root를 반환한다. 이 optional record는 SDK 모드가 아닌
기존 journal과 closure witness의 JSON/지문을 변경하지 않는다.

SDK 단계 시작·완료/실패/캐시 상태와 vertex별 stdout/stderr를 같은 가린 log store에 쓴다.
raw 오류 본문은 저장하지 않으며 vertex/stream의 부분 Secret matcher를 서로 섞지 않는다.
matcher의 공개 이름 필드와 본문 스트림을 구분하고 취소/중단의 Gap을 보존한다.

빌더의 input/output/cache는 허용된 노드 저장 root 아래 Engine이 정한 private 경로다.
앱이나 빌드 인자로 호스트 경로를 지정할 수 없다. 별도 Docker named volume을 생성하지
않으며, 기존 Engine bind guard가 각 Create·Copy·Start에서 dockerd가 보는 경로와 원
디렉터리 FD를 대조한다. 원 observations DB에는 root/job/input/output/cache의
장치·inode·UID/GID·권한을 보존한다. 알려진 디렉터리의 유실·교체·권한 변경을 새 경로
생성이나 권한 수리로 덮지 않는다. 아직 identity 저장 전인 준비 단계의 빈 할당만
초기화를 마칠 수 있으며 이미 데이터가 있는 미확인 디렉터리는 거부한다.

cache는 tenant/context/root/builder별로 원 job 하나가 배타 보유한다. 취소 요청만으로
반환하지 않으며 실제 원 container의 종료·제거 또는 확실한 미전송과 출력 reader의 종료를
확인한다. 작업 디렉터리 삭제 intent를 먼저 저장하고 unlink·부모 디렉터리 fsync 후
같은 DB transaction에서 작업 공간 정산과 cache 점유 반환을 확정한다. 삭제 뒤 DB 기록
실패는 원 intent로 재개한다. 삭제 intent 이전의 유실은 정리 성공으로 취급하지 않는다.
job 정리는 재사용할 cache 내용까지 삭제하지 않으며 준비 단계의 다른 job이 점유를
빼앗거나 해제할 수 없다.

등록 root의 durable consumer는 archive·job·cache로 나눈다. job/cache는 원 native
record에 borrow intent를 저장한 뒤 RootManager lease를 고정한다. 응답 유실 시 같은
consumer의 RecordedPin을 확인하며, 알려진 lease가 사라졌다고 새 borrow를 하지 않는다.
작업 파일과 I/O가 종료된 뒤 return intent→원 lease 반환→완료 기록 순서로 정산한다.
job 완료는 cache의 배타 점유만 반환하며 cache bytes가 사용하는 root 참조는 유지한다.
등록 root의 기존 consumer 수 제한을 자동 확대하지 않는다.

빌드 출력 형식은 OCI directory layout(`type=oci,tar=false`)이다. 성공 종료/Wait와 원 container 제거를 확인한
원 output FD를 결과 소비가 끝날 때까지 보유한다. 정지한 컨테이너의 재시작이 lazy reader와
경합하지 않도록 제거 전에는 출력을 열지 않는다. 디스크 hard quota는 보류이며
CPU·메모리·동시성·시간 제한과 구분한다. 이 native 어댑터의 Runtime 소비·결과 push와
전체 사용자 경로는 연결 중이다.

빌드의 live 로그는 원 container ID를 검사한 뒤 Docker SDK Attach로 받고 Docker의
영구 로그 저장(`LogConfig.Type=none`)은 사용하지 않는다. Create/Secret staging 뒤
Start 전에 연결하며 stdout/stderr는 별도 Secret prefix 상태로 가린다. 같은 원 job의
중복 attach는 거부한다. 취소/단절은 연결·reader·필터·descriptor 종료를 기다린 뒤
반환하며 daemon 오류 본문은 공개 실패에 넣지 않는다. 로그 EOF나 수신 중단은 Docker
Wait/종료 증거가 아니다. 재시작 후 유실된 로그를 raw history로 복원하지 않는다.
가린 로그 저장·페이지 조회는 아래 API를 사용한다. 실제 worker 전체 기동/종료 연결과
전체 사용자 경로의 마지막 검증은 진행 중이다.

