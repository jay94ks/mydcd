## 빌드 로그 페이지

User purpose8의 요청은 다음과 같다. 공통 Session/envelope 서명·Nonce와 현재 사용자
선택 규칙을 사용한다. Unix와 네트워크 SFCP가 같은 형식이며 새 socket은 열지 않는다.

```text
{Schema:1, Method:"image-build-logs", Nonce:[32], Params:{Tenant,
 Query:{Job, MaxBytes:1..24576, Tail?:true}, After?:cursor}}
```

성공 응답의 `Data` 형식은 다음과 같다. `[32]`는32바이트 배열이고 Data는
Go JSON의 base64 인코딩 byte 배열이다. 원 ZIP·Secret 값·사용자 자격은 포함하지 않는다.

```text
{Tenant, Job, Root:[32], Epoch, Phase, Next:cursor,
 Page:{Schema:1, Job:[32], Offset, Next, Total, Data,
       Available, Truncated, Gap, Unclosed}}
```

바깥 Job은 요청한 job 이름이고 Page.Job은 원 immutable Spec digest다. Phase는 공유
job의 `queued|running|unknown|succeeded|failed|cancelled`다. 로그 EOF와 별개이며
컨테이너가 살아 있다는 증거가 아니다. 현재 tenant Read 또는 ManageRegistry와 node
범위·설치 owner를 각 페이지 전후에 검사한다. 삭제된 기록은 conflict, 권한 상실은 denied,
원 owner/자료를 확인할 수 없으면 unavailable이다. queued의 아직 생성되지 않은 native
기록은 Available=false인 빈 페이지로 표현할 수 있다. running journal 유실을 빈 로그로 숨기지 않는다.

Offset/Next/Total은 저장된 **가린 bytes**의 위치다. cursor는 원 cluster/tenant/Spec/epoch와
offset에 고정하고 현재 job/root revision 변화로 무효화하지 않는다. 바깥 Next는 빈 페이지와
마지막 페이지에도 반환한다. 같은 Next를 다시 조회하여 이후에 추가된 로그를 읽을 수 있다.
다른 job/tenant/epoch의 cursor나 범위를 벗어난 offset은 거부한다.

첫 조회에 `Tail:true`를 지정하면 같은 DB snapshot에서 `Offset=max(0,Total−MaxBytes)`를
계산하여 마지막 페이지만 읽는다. 이전 페이지를 순회하지 않는다. 빈 로그와 MaxBytes보다
짧은 로그는 Offset=0이다. Tail과 비어 있지 않은 After를 함께 보내면 거부한다.
이어 읽을 때는 Tail을 생략하거나 false로 하고 응답의 Next를 After에 넣는다. 그러면
이전 bytes를 반복하거나 새 tail로 건너뛰지 않고, 그 뒤에 추가된 출력부터 읽는다.
권한·삭제·tenant/owner·epoch 검사는 일반 조회와 같다. Tail 생략 시 기존 요청 JSON과
응답 형식은 유지하며 스키마 번호는1이다.

job당 최대8MiB를 같은 node observations DB의8KiB 조각으로 보관한다. 초과하면 Truncated를
남기고 SDK 출력을 계속 소비한다. Unclosed는 마지막 로그 session의 종료가 저장되지 않은
상태이며 현재 실행 중임을 뜻하지 않는다. 새 session을 열면 이전 bytes를 보존하고 Gap을
표시한다. 첫 session의 스트림 단절·강제 종료도 Gap으로 표시할 수 있다. 누락된 출력을 Docker raw history로 복원하지 않는다. 로그 writer/stream이
끝나야 workspace/root를 정산할 수 있다. 기록 삭제의 Raft 확정과 원 native completion을
확인한 owner만 로그 bytes를 회수하며 원 job/종료 증거는 보존한다. worker의 삭제 sweep
연결과 전체 경계 검증은 RQ6에 포함한다.

```sh
sfcli build logs build-one
sfcli build logs build-one --tail
sfcli build logs build-one -f
```

CLI는 페이지를 차례로 읽어 출력하고, `-f`는 빌드가 끝날 때까지 계속 읽는다. SDK `Client.ImageBuildLogs`는 MaxBytes·페이지 길이·
대상 tenant/job·원 cursor root/offset과 다음 cursor를 검증한다. UI 구현은 별도 작업 범위다.


출력은 `oci-layout`의 외부 규격 1.0.0과 하나의 결과를 가리키는 `index.json`을 사용한다.
결과가 다중 플랫폼 index이면 flatten하지 않고 그 index와 하위 manifest를 보존한다.
기존 registry manifest 코어가 descriptor 관계·깊이·metadata/이미지 크기 예산을 검사하고,
출력 reader는 참조된 실제 config/layer의 길이와 SHA-256을 일정 메모리로 확인한다.
symlink·장치/FIFO·다른 파일의 hardlink·외부 URL/inline descriptor는 읽지 않는다.
이 예산은 기존 registry 입력/metadata 경계이며 파일시스템 hard quota를 뜻하지 않는다.

OCI 라이브러리는 확인한 원 layout FD에서 읽는다. 라이브러리의 lazy layer/config I/O가
끝난 뒤 해당 reader를 닫아야 작업 공간 삭제와 cache 점유 반환이 가능하다. 검사 실패 시
reader를 반환하며 원 작업의 실패·정리는 실제 owner가 별도로 정산한다. 출력 검사 성공은
registry 게시나 공유 job 성공의 증거가 아니다.


