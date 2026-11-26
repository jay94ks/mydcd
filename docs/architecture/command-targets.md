# 명령어 적용대상 맵핑표

| 빌드 job의 registry I/O | 인증·대상 | 제한 |
|---|---|---|
| member `image-build-registry-permit` → OCI BuildSubject (`mydc-build`) | 원 installed builder node·수락된 job Snapshot/현재 권한·내장 registry Run/Generation | pull은 trust/회수 fence, push는 running/unknown job의 정확한 출력 repository. Session/Task와 배타적이며 bearer는 registry owner가 발급. 취소/종결 뒤 새 I/O 거부. [포맷](../reference/image-build-jobs/04-owner.md) |

| 이미지 빌드 job | 인증·대상 | 원 결과/수명 |
|---|---|---|
| `build run CONTEXT [VERSION]` → User `image-build-job-plan` / `begin-image-build` | 선택 cluster/tenant/user ManageRegistry와 begin-image-build ceiling, Secret 공급은 Deploy도 필요. 현재 owner/root·context/policy·registry generation·고정 snapshot | 같은 원 journal/CAS. build의 --no-input/--group-password-fd는 원 build purpose의 Group 승인. 이미 확정한 원 작업은 재승인하지 않음. [형식·예산](../reference/image-build-jobs.md) |
| `build list/show` → `image-builds Part:jobs` | 현재 tenant Read/ManageRegistry, Job/Context 고정 cursor | 공개 상태·원 version·creator·결과만 반환, 원 grant/Secret 값 비노출 |
| `build cache prune` → `prune-build-cache` typed change / User `image-builds Part:cache-prunes` 조회 | 현재 tenant/node ManageRegistry로 수락; 조회 Read/ManageRegistry; 내부 `image-build-cache-prune-work/report`는 설치 원 owner와 latest quorum | 원 cache/보존 source Spec digest·root·사용자 승인을 고정. 먼저 수락된 빌드 뒤, 이후 빌드 앞에 순서 보존. pending builder 이미지를 삭제에서 보호. 원 Runtime/native 수명·서명 완료와 공통 예산을 사용하며 accepted/queued와 실제 정리 완료를 구분. 전체 사용자 경로의 검증 근거와 코드 연결을 구분 ([형식](../reference/image-build-jobs/14-section.md)) |
| `build cache prune [CONTEXT] [--node NODE]`(cache마다 change 하나) | 계획은 현재 tenant/node Read/ManageRegistry 목록, 제출은 각 scope의 현재 ManageRegistry/operation ceiling·원 사용자 서명 | 같은 inventory/epoch의 정렬된 대상과 deterministic child ID를 JSON으로 고정. apply는 기존 단일 정리를 순차 제출하고 거부/불명에서 suffix를 멈춤. 각 journal/CAS/권한을 유지하며 전체 atomic/완료로 표시하지 않음. 원 목록을 재탐색하지 않음 |
| `build cache list [CONTEXT] [--node NODE]` → User `image-builds Part:caches` → member `image-build-caches-owner` | 현재 tenant/node Read/ManageRegistry; 원 page/owner를 전후 재검사 | 같은 cache namespace의 job을 묶어 최대4행. 삭제된 job의 캐시·queued 대표와 원 관측을 분리하고 UNAVAILABLE을 usage0으로 바꾸지 않음. 조회로 cache/root/native를 생성하거나 정리를 실행하지 않음 |
| `build cache show CACHE --node NODE` → User `image-build-cache`의 Cache/Node selector → member `image-build-cache-owner` | 현재 tenant/node Read/ManageRegistry·보존 원 cache identity·설치 owner를 전후 확인 | 삭제된 job/컨텍스트의 cache 항목도 읽음. 원 관측/cache/epoch cursor로 대표 교체와 구분. 혼합 selector·다른 scope·유실된 원 native 증거 거부; job 기록 재개/생성·삭제를 하지 않음 |
| User `image-build-cache` → member `image-build-cache-owner` | 현재 tenant Read/ManageRegistry·원 node 범위·설치 owner; 페이지 전후 현재 권한 | 같은 tenant/context/root/builder 캐시의 마지막 실제 SDK 관측. 관측 시각/원 job·최근 실패·배타 참조를 구분하고 항목 최대32개를 반환. 조회로 빌더 기동/새 job·삭제를 하지 않음. optional Cleanup은 원 빌드 종료 자동 정리의 의도/ACK·Unknown이며 조회는 재전송하지 않음 |
| `build logs BUILD [-f] [--tail]` → User `image-build-logs` → member `image-build-logs-owner` | 현재 tenant Read/ManageRegistry·node 범위·설치 원 owner; 각 페이지 전후 현재 권한 확인 | 가린 node-local bytes만 최대24KiB 조회, job당8MiB. Tail은 마지막 MaxBytes로 바로 이동하고 After와 혼합 거부. 원 Spec/tenant/epoch/offset Next로 새 출력만 이어 읽음. Truncated/Gap/Unclosed와 공유 Phase를 구분하며 새 build/관리 변경을 만들지 않음 |
| `build cancel/delete BUILD` | 현재 tenant ManageRegistry cleanup, 원 job Revision CAS/명시 request ID | 취소는 참조를 반환하지 않음. owner closure 뒤 기록을 tombstone으로 삭제한 다음 version 삭제 허용 |
| member `image-build-job-work/image-build-job-report` | 설치된 원 owner·원 accepted grant·현재 정책/권한·quorum/root/epoch | begin의 고정 FROM·서명된 Sources(reader/read-set 또는 managed run)·공유 동시성·node/tenant 공통 CPU/메모리 예약, cancel/unknown에서도 예산 보존 후 terminal owner closure로 반환. 종료 증거의 원 At은 보존하고 현재 보고 envelope의 At/CAS/epoch와 구분. Work.Blocked의 slot/budget 대기를 취소/회수와 구분. 실제 worker는 SDK solve의 Sent/원 결과와 daemon 종료를 구분해 보존하며, 원 Outcome을 먼저 고정하고 native/I/O/게시 정산 뒤 terminal을 보고하며 shutdown으로 새 사용자 명령을 만들지 않음. 사용자 관리 권한을 node 키로 대체하지 않음 |
| member `image-build-cache-automatic-report` → 기존 `image-build-cache-prune-work/report` | 설치 cache owner·현재 정책의 원 accepted 사용자 승인/서명과 현재 권한·root/builder·latest quorum/CAS/epoch | idle scope의 현재 자동 slot/단조 Sequence. 실제 종료 후에만 다음 pass 수락. 원 Source Spec과 현재 실행 정책을 분리하고 기존 유한 worker·공통 예산을 사용. 사용자 session/명령을 합성하지 않음. 조회는 현재 `build-cache-prunes` 행의 Automatic/Sequence. [주기 정책](../reference/image-build-jobs/16-idle-cache.md) |
| member `image-build-base-work/image-build-base-owner` | 원 builder/job/Spec·current quorum/accepted 권한·현재 신뢰·원 source owner/reader 승인 | 공개 manifest/digest만 반환. queued의 원 Dockerfile sources를 해결하고 begin 뒤에는 고정 digest 재조회. source 자격/사용 참조는 원 reader에 보존하며 begin 뒤 원 binding의 owner/generation/read-set과 일치해야 함. 원 job 종결 전 reader/run 반환을 거부하고 폐기 source의 익명 fallback이나 다른 node의 job 사용을 허용하지 않음 |
| member `image-build-base-tls-owner/image-build-registry-tls-owner` | 설치된 원 Builder→source/registry owner·current quorum·원 begin/reader/ReadSet 또는 고정 permit/run/serving leaf | 공개 X.509 DER와 authority/managed leaf fingerprint만 반환. CA 누락·미선택 CA·다른 owner/generation·취소/폐기를 거부. private key/password/Vault 원문·host trust 변경 없음. job의 읽기 전용 daemon 설정과 호출별 publisher client에 한정 |
| member `image-build-base-token-owner` | 설치된 원 Builder→source owner·current quorum·running/unknown의 원 begin/source binding | Read/Additional와 Host/Realm/Service·최대8개 frozen repository의 정확한 pull scope를 대조. 같은 job/owner·external reader 선택/세대·ReadSet만 결합해 실제 registry challenge 뒤 token만 보호 응답. queued·미선택 repository/push/catalog·다른 owner/reader·managed 복수 scope를 거부. password/refresh token/CA·token의 Raft/관측/log 보존 없음. native BuildKit solve 연결과 구분 |
| member `image-build-secret-inputs` → SecretFetch의 AppInputFetch.ImageBuild | 원 installed builder owner·running job Snapshot·현재 Deploy/ManageRegistry·build purpose 승인/usage | provider의 원 leaf/ReadSet/MinimumIndex만 읽음. Task/Move/외부 registry 선택자 혼합 거부. terminal의 원 UseGone으로만 반환하고 공개 조회에 값/Grant를 내보내지 않음 |

| 보존 빌드 컨텍스트 조회 | 인증·적용대상 | 수명·포맷 |
|---|---|---|
| `build context ls/cat CONTEXT` → User `build-context-content` → member `image-build-content-owner` | 선택된 cluster/tenant/user의 현재 Read 또는 ManageRegistry, 원 owner/node/root ACL·epoch·consume된 미삭제 version | 8개 tree 항목/24KiB Dockerfile 또는 regular file bytes와 원 version/tree/Part/Path/epoch cursor. file의64-bit Offset/크기·원 tree 지문/실행 bit를 반환하고 전체 다운로드는 EOF 지문을 확인. 원 root pin·inode·seal을 확인하고 GC와 같은 gate에서 복사. 없는 원 자료 재생성·다른 tenant/임의 경로 조회 금지. [메시지](../reference/image-build-contexts/04-dockerfile.md) |

| Git build source 확인 | 인증·적용대상 | 범위 |
|---|---|---|
| `put-build-context`의 Git.Automatic → member `image-build-automatic-git-report` → 기존 builder worker | 원 accepted 사용자 정의·현재 계정/credential·put/publish/begin ceiling·ManageRegistry·정확한 node/root와 현재 관측/context/policy. Secret은 Deploy와 해당 build purpose 승인 필요 | 원 SavedGit·고정 auto ID·시작 시간/의도 지문으로 archive/version/queued job·Secret usage를 같은 FSM에서 수락. 버전 번호는 FSM이 할당하고 native/Secret은 실제 Spec 지문 사용. 기존 job/tombstone 재제출 거부, 다음 commit은 기존 terminal 대기. Vault 승인 API의 Origin에는 원 put-build-context operation을 전달하며 새 사용자/노드 CLI 명령을 합성하지 않음. [형식](../reference/image-build-contexts/17-git.md) |
| Automatic Git 관측 → member `image-build-git-observation-report`; `build context list/show`/User `image-builds Part:contexts`의 GitObservation 조회 | 원 put-build-context의 accepted 사용자·현재 credential/ceiling·ManageRegistry, 정확한 work node/root와 현재 context/policy/epoch. 조회는 현재 tenant Read/ManageRegistry | 기존 유한 source 검사와 owner signed 관측/원 CAS. 설정 revision·원 정의/version/job은 유지하고 같은 결과는 반복 기록하지 않음. 관측 At는 마지막 변경 결과의 시각이며 자동 archive/build 수락·실행 성공과 구분. [포맷](../reference/image-build-contexts/16-git.md) |
| `build context upload CONTEXT`(Git 컨텍스트) → User `save-build-git` → member `image-build-git-owner` | 선택 cluster/tenant/creator의 현재 ManageRegistry·publish operation ceiling, 고정 commit/tree·context/policy/root·ID/기한과 사용자 session-key proof | plan은 원 source 확인/현재 metadata 일치만 조합. save는 원 native archive를 보존하고 별도 manage apply용 unsigned ChangeDocument 출력. 기존 원 save는 ref 재조회/재생성하지 않으며 PENDING/원 결과·현재 권한을 유지. [포맷](../reference/image-build-contexts/14-git-archive.md#git-보관의-사용자-메시지와-cli) |
| `manage apply` action `publish-build-git` | 선택 tenant의 현재 ManageRegistry·원 creator와 publish operation ceiling, SavedGit의 원 context/policy/root·기한. Expected=원 ContextRevision | 노드의 보관 증거를 사용자 signed User/Raft 변경으로 게시. version/closed artifact/commit/다음 번호를 원자 확정하고 원 version/job/reader/GC 참조 사용. native 보관과 Raft 게시를 구분하며 실제 이미지 build/push 성공을 뜻하지 않음. [포맷](../reference/image-build-contexts/14-git-archive.md) |
| `build draft freeze CONTEXT` → User `build-draft Kind:freeze` → `publish-build-draft` | 원 Scope/Creator·선택 revision/지문·ID/기한과 현재 ManageRegistry/publish operation ceiling, native root owner; 게시는 원 creator의 별도 signed User/Raft 변경 | 원 inode archive를 같은 Spool에 인계하고 owner 증거만 반환. ChangeDocument는 아직 사용자 승인이 아님. Expected는 원 draft revision, FSM에서 다음 version/closed archive를 원자 게시. 같은 ID/내용 결과와 version/job/reader/GC 참조 보존. [포맷](../reference/image-build-contexts/12-draft-freeze.md) |
| User `build-draft Kind:result` → member `image-build-draft-owner` | 현재 ManageRegistry·put-build-context ceiling·tenant/node 소유권, 원 Scope/Edit 지문에 대한 새 result-purpose 사용자 proof | 과거 설정/삭제 뒤에도 원 metadata 결과만 조회. 원 결과·PENDING·DISCARDED·기록 부재를 구분하고 새 pin/파일/편집·ID/CAS/Scope retarget을 하지 않음. 과거 편집 승인을 현재 조회 권한으로 대체하지 않음. [포맷](../reference/image-build-contexts/06-draft.md#과거-편집의-원-결과-조회) |
| 결과 조회 User `build-draft Kind:freeze-result` / `git-save` result(CLI 명령 없음, `op show`가 게시 작업을 확인) | 현재 creator·ManageRegistry·해당 publish operation ceiling·원 plan의 result-purpose proof와 같은 root/단조 설정 계보 | 만료/설정 변경·삭제·본문 회수 뒤 기존 native 결과만 조회. 저장된 seal에서 같은 원 증거를 복원하고 완료/PENDING/DISCARDED/기록 부재와 확인된 Reclaimed를 구분. fetch/파일/pin·seal 저장·게시/ChangeDocument 생성 없음. [포맷](../reference/image-build-contexts/15-freeze-git.md) |
| `build draft ls/cat/put/rm/mv CONTEXT` → User `build-draft` → member `image-build-draft-owner` | 선택 cluster/tenant/user의 현재 ManageRegistry·put-build-context operation ceiling, 원 context/policy/root scope, 편집의 사용자 session-key proof | mutable owner-local 입력만 다룸. plan은 native 생성 없음. 설정 변경 뒤 fresh Scope는 같은 데이터 생성 수명/파일/revision을 사용하지만 과거 Scope의 권한을 자동 연장하지 않음. 원 edit ID/결과는 보존하고 삭제 후 재생성은 새 수명. tree는8항목과 같은 revision/지문 cursor, file은 원 Scope/Revision/Digest/Path/Offset의24KiB 조회로 과거 tree·미완료 bytes를 거부하며 Read-only 불가, edit는 고정 ID/CAS와 metadata 또는24KiB inline 파일. file-part/status/seal은 같은 put edit의 최대500MB 파일을24KiB 조각으로 stage하고 전체 검증 뒤 원 CAS로 등록. 원 결과/partial inode 보존, 새 ID/자동 retarget 금지. owner의 미사용 본문 정리는 edit 결과와 현재 CAS의 pending/트리 참조를 보호. CAS가 지나간 미완료 본문은 원 편집 폐기 표시 뒤 회수하며 원 file-part/status/seal은 충돌로 거부. 회수 중인 본문으로 새 편집 참조를 만들지 않고 PENDING 반환. immutable version 게시·빌드 수락은 별도 User/Raft 변경. [포맷](../reference/image-build-contexts/06-draft.md) |
| `build context check CONTEXT` → User `check-build-context` → member `image-build-source-owner` | 선택된 cluster/tenant/user의 ManageRegistry와 허용 owner/root·등록 context/policy/epoch·설치 tenant/profile/exact repository | 원 source를 fixed commit으로 읽어 ZIP/tree/Dockerfile·모든 target FROM trust 확인. 응답은 공개 코드/지문·개수, build/version/push 수락 아님. 임의 URL/credential 입력이나 앱 CD 실행을 허용하지 않음 |

| 빌드 자료 종료/회수 | 인증·대상 | 수락/완료 경계 |
|---|---|---|
| `manage apply` action `delete-build-version` | tenant ManageRegistry·version ID/Number CAS·등록 사용자 operation | 보존 버전을 명시 삭제 상태로 전환. native bytes/root pin 종료는 owner closure까지 대기 |
| Management `image-build-artifact-work` / `image-build-owner-report` | 설치된 원 owner key·고정 upload scope, 현재 RootRevision/Epoch와 원 uploader revision | expiry는 고정 시점 서명, reclaim은 실제 file tombstone/원 pin 반환의 서명 증거. 다른 owner·보존 version·불명 정리는 거부 |

| ZIP 전송 명령/메시지 | 인증·대상 | 원 결과·재개 |
|---|---|---|
| `build context upload CONTEXT FILE.zip [--id ID]` | 선택 cluster/tenant/user의 ManageRegistry·원 creator, 등록 context/node/root와 정확한 원 파일 지문 | 원 begin/consume generic journal·기존 legacy part journal부터 조회. 새 begin만 Session JSON≤8KiB에서 ChunkBytes32768, 그 밖에는 legacy0/24KiB를 선택. 원 begin/Scope의 크기·서명·offset은 재개에서도 고정. 새 part는 사용자 서명 Record와 owner report의 확정 ACK revision을 다음 CAS로 연결. 초기/최종 조회와 legacy 정산 뒤 cache 갱신, seal 전 원 scope/revision/완료 대조. 별도 per-part UserOperation 없음. 불명은 같은 파일/prefix의 명시 resume·원 slot ACK 회수, 새 ID/CAS/epoch 없음. 결과는 immutable context version |
| User `build-zip-transfer` / Management `image-build-owner`·`image-build-io-permit`·`image-build-part-permit` | 현재 Session/원 part proof·fixed upload scope/ChunkBytes/CAS·현재 owner와 quorum | part-permit는 Data 없는 typed metadata의 current quorum 조회이며 쓰기/봉인 효과가 아님. fullData permit와 seal 경로는 유지하고 실제 owner는 원 Data 길이/SHA를 검사. Record는 사용자 proof에 서명되며 true인 part만 원 signed begin/scope·현재 권한·native receipt로 owner report를 확정. SDK 생략/false는 기존 stage-only·legacy 경로. 같은 bytes의 원 slot에서 ACK를 회수하고 새 empty upload로 바꾸지 않으며 fd 종료/abort가 artifact lease 반환이 아님. [포맷](../reference/image-build-contexts/05-zip.md) |

| 이미지 빌드 명령/메시지 | 인증·적용 대상 | 경계 |
|---|---|---|
| `build policy show`·`build context list/show/versions` → User `image-builds` | 현재 tenant Read 또는 ManageRegistry, 선택된 Linux user의 cluster/tenant/user 프로필 | 공개 metadata만 최대8개/96KiB page. 현재 root/epoch cursor와 `--after` 사용. [세부 명세](../reference/image-build-contexts.md) |
| User `image-builds Part:uploads/missing`(`build context upload`이 읽음) | 위 권한과 원 upload creator ID | 다른 관리자도 원 creator를 대체하지 않음. missing 최대256개. Scope/진행 조회는 실제 builder 실행 성공이 아님 |
| `manage apply`의 set/delete-image-build-policy·put/delete-build-context | tenant ManageRegistry, node/root의 현재 ACL·설치 소유권, policy/context record CAS와 outer root CAS | tenant 관리 명령 허용. app.yaml/CD와 로컬 프로필 등록에 합치지 않음 |
| begin-build-zip-upload·put-build-zip-part·upload-build-zip·abort-build-zip-upload | tenant ManageRegistry·원 creator·원 scope, upload CAS | begin/consume/abort와 legacy part는 명시 UserOperation. 새 Record part는 기존 image-build-owner-report Action:part로 확정하며 per-part journal을 만들지 않음. legacy part의 owner receipt·원 result/resume/journal은 보존. consume는 owner seal과 버전 생성/종료의 원자 변경. raw bytes stage·native 회수·builder는 별도 연결 범위 |

외부 registry의 `registry external list/show NAME`와 User `external-registries`는 선택 tenant의 공개 참조만 읽는다(Read 또는 ManageRegistry). `put-external-registry`/`delete-external-registry`는 tenant ManageRegistry의 관리 변경이며 앱 선언으로 생성하지 않는다. payload·record/root CAS·삭제 흔적·민감 값 공급의 현재 경계는 [외부 registry 명세](../reference/external-registries.md)를 따른다. delete는 tenant 종료 중 cleanup 권한을 허용하며 원 Secret이나 실행 중 컨테이너를 삭제하지 않는다.

유한 User 요청은 client write EOF를 검증한 뒤 응답·업무 처리로 진행한다. 빠른 denied도 같은 순서이며 trailing byte는 거부한다. 이는 기존 서명·scope·quorum·원 operation/Unknown 정책을 변경하거나 자동 재제출 권한을 추가하지 않는다. 별도 입력 stream의 continue/body/EOF는 [Unix API](../reference/unix-sockets.md)를 따른다.

| 관측 명령·별칭 | 적용대상 | 현재 권한·효과 |
|---|---|---|
| `manage node-summary [--node NODE] [--after CURSOR] [--system]` | 선택 tenant의 허용 node 또는 명시 system 전체 | tenant Read / system-admin ManageCluster. 다른 tenant 사용량·호스트 metadata를 tenant 응답에 넣지 않음 |
| `manage node-disks` / `node disks [NODE]` + 같은 필터 | 승인된 system/Docker data-root/등록 root | 전체 system-admin 또는 tenant ManageVolumes. 허용 root부터 고른 뒤 같은 파일시스템 중복 제거. 디스크 변경 없음 |
| `manage node-tenant-usage --node NODE [--after CURSOR]` | 선택 node의 tenant별 관측/예약/한도 | system-admin ManageCluster. node-summary의 TenantsNext 사용 |
| `manage mesh-links` / `mesh links` + 같은 필터 | 전체 node 쌍 또는 tenant 허용 node 쌍 | system 관리자 상세 / tenant Read 상태 요약. 링크 재설정 없음 |
| `manage raft-status` / `raft-status [--after CURSOR]` | 연결한 node의 로컬 합의 진단 | system-admin ManageCluster·현재 Session을 로컬 마지막 적용 catalog로 확인. 단절 시 stale, 관리 변경의 quorum 정책을 우회하지 않음 |

각 명령은 [노드 관측 API](../reference/node-observations.md)의 같은 User method로 전달한다. 결과가 실행/용량 확보 권한을 뜻하지 않는다.

`manage tasks [--app NAME] [--node NODE] [--after CURSOR] [--all-tenants]`는 현재 사용자 Session으로 수락된 Task·서명 관측을 읽는다. 기본 적용대상은 선택 tenant이며 `--all-tenants`도 현재 Read·membership·허용 node 범위만 반환한다. 관리 변경·provider 입력·native 제어를 수행하지 않는다. MYDCP method는 `tasks`이고 [행·cursor 계약](../reference/task-observability.md)을 따른다.

| 원문 조회 명령 | 적용대상·입력 | 권한·효과 |
|---|---|---|
| `manage app-source --app NAME [--deployment ID] [--revision VERSION] [--section source\|local-services\|overlays] [--raw]` | 선택 tenant의 수락된 앱·고정 보존 버전. 기본 최신 수락 버전 | 현재 Session tenant Read. 원문/별도 local-services YAML/CD overlay를 읽으며 배포·provider fetch·원 operation 변경 없음 |
| `manage app-revisions --app NAME [--deployment ID] [--after CURSOR]` | 같은 앱의 보존 버전 목록 | 같은 Read, root/사용자/scope/선택자 고정 페이지. 이력 회수는 기존 rotate-app-history 별도 명령 |

MYDCP method는 각각 `app-source`·`app-revisions`다. [형식·원문 분할·이력 회수](../reference/app-source.md)를 따른다.

명령의 적용대상·입력·효과를 정의하는 기준표다. 자원의 생성/삭제 주체는 [자원표](resource-ownership.md), 파일의 책임은 [app.yaml·cluster.yaml](app-and-cluster-spec.md), 프로필 선택은 CLI 선행 계약을 함께 따른다. 실행 가능한 문법은 [현재 CLI](../configuration/cli.md)와 구현된 도움말이 기준이다. 이 표는 현재 명령과 내부 API의 책임 경계를 기술한다. 실제 후속 도구는 별도로 표시하며, 실행/완료 내역은 HISTORY, 남은 작업은 MILESTONES에서 관리한다.

## 절 목록

이 문서는 절마다 파일로 나뉘어 있다.

| 절 | 파일 |
|---|---|
| 대상 결정과 원 작업 보존 | [command-targets/01-section.md](command-targets/01-section.md) |
| 로컬 설정·접속·계정 | [command-targets/02-section.md](command-targets/02-section.md) |
| 앱 선언과 tenant 관리 변경 | [command-targets/03-tenant.md](command-targets/03-tenant.md) |
| Secret·Volume·노드 운영 | [command-targets/04-secret-volume.md](command-targets/04-secret-volume.md) |
| 설치 신원 경로와 관리 도구의 분리 | [command-targets/05-section.md](command-targets/05-section.md) |
| 유지 규칙 | [command-targets/06-section.md](command-targets/06-section.md) |
| Tenant 전체 삭제 | [command-targets/07-tenant.md](command-targets/07-tenant.md) |
| 컨테이너 운영 조회 | [command-targets/08-section.md](command-targets/08-section.md) |
| 계정·tenant typed 변경 payload | [command-targets/09-tenant-typed-payload.md](command-targets/09-tenant-typed-payload.md) |
| 이미지 본문 조회 | [command-targets/10-section.md](command-targets/10-section.md) |
| Ingress 운영과 인증서 | [command-targets/11-ingress.md](command-targets/11-ingress.md) |
| 서비스·Git 진단 대상 | [command-targets/12-git.md](command-targets/12-git.md) |
| 단독 컨테이너·Volume 파일 | [command-targets/13-volume.md](command-targets/13-volume.md) |
| 관리 자원 읽기 대상 | [command-targets/14-section.md](command-targets/14-section.md) |
| Lifecycle 원본 도구 | [command-targets/15-lifecycle.md](command-targets/15-lifecycle.md) |
