# lifecycle-compiler

컴파일러 컨테이너의 이미지 정의·entrypoint·빌드 자료는 이 디렉터리에 둔다. [native owner](../../internal/workload/lifecycle/compiler_native_linux.go)의 원 Create/Start·복구·Stop/Wait/제거와 [cache collector](../../internal/workload/lifecycle/compiled_collect_linux.go)·원 closure 보고를 연결한다. [Runtime builder 소비](../../internal/app/checker_builder.go)가 원 shared job의 local 수락·같은 source/SDK/manifest 준비와 dispatch/native Step를 연결한다. app job 생성/배치·cache hit/miss·member artifact 소비·compiled CLI 실행에 연결되어 있다. L1 마지막 검증에서 실제 compiler/앱 소비·재개/정산을 확인하며 코드 연결만으로 성공을 주장하지 않는다.

| 파일 | 책임 |
|---|---|
| [main.go](main.go) | 고정 입력 경로의 유한 batch 한 번을 처리하고 종료하는 entrypoint |
| [Dockerfile](Dockerfile) | 명시 확보한 정적 executable/toolchain으로 구성하는 scratch 이미지, UID/GID 10001 |
| [prepare_context.py](prepare_context.py) | 기존 로컬 toolchain과 미리 빌드한 executable을 새 이미지 context에 복사. 다운로드·이미지 빌드·컨테이너 기동은 수행하지 않음 |

source 검증·manifest·offline Go 실행·ELF/read-back 검사는 [제품 compiler 코어](../../internal/workload/lifecycle/compile_exec_linux.go)를 직접 사용한다. 이미지 context는 저장소 밖 승인된 작업 경로에서 만들며 `--toolchain`, `--toolchain-version`, `--compiler`, `--out`을 모두 명시한다. 선택 `--registry-cache`는 같은 로컬 rootfs를 immutable Registry V2 시험 cache로 내보낸다. 기존 context의 `export_registry`도 재사용할 수 있으며 이미지 pull/build/실행은 하지 않는다. L1 owned fixture의 `SFC_LIFECYCLE_COMPILER_CACHE` 입력은 이 cache를 기존 시험 registry로 제공하고 정확한 digest를 SDK로 명시 import한 뒤 정책/job을 수락한다. 일반 compiler owner는 local-only image inspect를 유지한다. 시험 소유 import는 원 reference/config를 먼저 manifest에 기록하고 consumer 종료 뒤 Engine conflict 검사로 제거하며, 별도 `SFC_LIFECYCLE_COMPILER_IMAGE` 사전 설치 입력은 보존한다. 고정 toolchain/entrypoint 빌드와 이미지 생성은 L1 마지막 검증에서 기존 cache를 사용한다. 자동 다운로드나 일반 daemon 기동 시 이미지 빌드를 추가하지 않는다.

동작은 D6 컴파일 계약을 따른다.

1. 평소에는 실행 중인 compiler 컨테이너/프로세스가 없다. daemon 기동이나 정책 등록만으로 compiler를 실행하지 않는다.
2. 내구 수락된 compile job에 필요한 cache miss가 있을 때만 tenant가 허용한 node에서 compiler를 시작한다. 검증된 cache hit와 compile=false는 compiler를 기동하지 않는다.
3. 한 번의 유한 batch를 offline으로 컴파일하고 검증한 산출물을 tenant compiled cache에 게시한다. 새 job을 기다리는 idle loop나 상시 worker를 두지 않는다.
4. 성공·실패·취소 모두 원 컨테이너의 종료/Wait를 확인하고 임시 workspace를 정산한다. 정상 완료에는 컨테이너 제거까지 포함하며 이미지와 승인된 cache는 재사용할 수 있다.
5. 응답 불명이나 daemon 재기동 시 원 job/native ID를 먼저 복구한다. 종료 확인 전 새 compiler를 중복 생성하거나 원 pin을 반환하지 않는다.

유휴 상태는 일시정지한 컨테이너나 대기 프로세스를 유지하는 상태가 아니다. 정상 정산 후에는 compiler 컨테이너를 제거하고 이미지·승인된 cache만 보존한다. 다음 cache miss job은 새 job에 속한 유한 컨테이너로 처리한다. 종료가 확인되지 않은 이전 job은 이 유휴 상태로 간주하지 않는다.

실제 runtime workspace는 node 저장 정책 아래 tenant/job별로 격리한다. 이 저장소 디렉터리를 writable bind로 주거나 host Docker socket·앱 Secret/Volume을 compiler에 제공하지 않는다. 고정 toolchain/image digest·자원 한도와 실제 종료 확인은 구현 시 같은 계약으로 연결한다.

이미지는 입력 `/input`을 읽기 전용으로 제공받고 `/work`·`/output`·승인된 `/cache`만 해당 job/tenant에 맞춰 제공받는다. node adapter는 해당 경로의 UID/GID 접근·disk/CPU/memory/PID 한도·네트워크 차단을 실제 실행 전에 구성한다. entrypoint의 batch 반환이나 report만으로 이 격리·Docker 종료·cache 등록이 완료되었다고 판단하지 않는다.
