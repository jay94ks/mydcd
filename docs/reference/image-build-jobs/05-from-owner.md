## FROM 본문의 owner 소비

새 SDK 작업은 Create 전에 native `Solve.SourceContent:true`를 고정한다. BuildKit의
source policy가 원 Dockerfile의 승인된 tag와 digest를 정확한 `oci-layout://` 참조와
job-private OCI store ID로 전환한다. 고정 digest 이외의 이미지·다른 store/session은
거부하며 Dockerfile 텍스트·frontend·platform·image config/ONBUILD 처리는 원 SDK에
맡긴다. FROM/COPY/mount의 이미지 읽기에 같은 경계를 쓴다.

각 store는 원 frozen FROM root와 source에 고정한다. 설치 builder가
[ImageContent kind16](../image-content.md#수락된-빌드의-from-본문)로 원 owner에서 읽으며,
local owner도 같은 body 검증 코어를 사용한다. Basic-only·repository별 reader 및
내장 registry의 인증/TLS 검증은 해당 owner가 맡는다. password/토큰/CA를 builder의
호스트별 credential로 합치지 않는다. cache된 본문도 현재 job/source 권한을
최대8MiB 또는1초 간격과 각 본문 끝에서 다시 검사한다.

SDK의 content.Store는 임의 위치 ReaderAt을 요구한다. metadata는 store당16MiB
이내 메모리에 보관하고 layer는 원 solve 출력 디렉터리의 이름 없는0600 임시 파일에
일정 메모리로 기록한다. 원 owner의 최종 성공·길이/지문이 모두 맞은 본문만 SDK에
노출한다. 같은 store의 반복 range/공유 layer는 재다운로드하지 않는다. 파일은 해당
solve의 세션에만 속하며 별도 영속 cache·DB·listener를 만들지 않는다. O_TMPFILE
미지원 시 원 디렉터리에서 배타 생성한 파일의 inode를 확인해 unlink/fsync한 뒤
본문을 쓴다. 그 전 crash의 빈 잔여 파일은 기존 전체 작업 공간 정리 대상이다.

원 Solve 종료 뒤 store의 I/O를 취소·join하고 모든 file을 닫은 다음 원 작업 공간을
반환한다. source 읽기 실패와 로컬 파일 저장 실패를 SOURCE_FETCH와
STORAGE_UNAVAILABLE로 구분한다. 기존 native 기록의 SourceContent 부재/false는
원 token/daemon TLS 방식을 유지하며, Sent 이후 새 방식으로 재실행하지 않는다.
자체 schema 번호는1이다.

