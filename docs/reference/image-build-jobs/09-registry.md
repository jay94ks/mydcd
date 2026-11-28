## 결과 registry 게시와 응답 유실

게시 대상은 수락된 job의 출력 repository·순서 있는 태그 목록과 원 OCI digest/크기에
고정한다. 같은 node observations DB의 publication 기록이 각 태그의 의존 blob 업로드
시작과 최종 root manifest PUT 전송 의도를 구분한다. 실제 쓰기 직전에 현재 job 권한을
다시 확인하고 기록을 동기 저장한다. 기존 고정 OCI SDK로 이미지 또는 다중 플랫폼 index를
전송하며 별도 registry 프로토콜·키 저장소·Docker import를 만들지 않는다.

태그 PUT의 응답 유실·서버 오류·202 Accepted·다른 digest를 가리키는 응답 header는
성공으로 확정하지 않는다. 원 SDK 호출은 자동 재전송하지 않고 그 태그의 게시를 불명으로
보존한다. 원 인증 경계에서 조회한 태그가 원 digest·media type·manifest 크기와 일치해야
잃어버린 결과를 정산할 수 있다. 조회 실패·부재·다른 이미지로의 변경은 미실행 증거가
아니며 새 PUT을 허가하지 않는다. 불명인 태그 다음의 태그도 아직 게시하지 않는다.

확실히 게시된 태그의 완료 기록을 보존하고, 모든 태그를 확인한 뒤에만 성공 결과를 만든다.
앞의 태그가 확인되고 뒤에서 확실한 실패가 발생하면 부분 게시를 실패로 정산하며 기존
태그나 content를 자동 삭제하지 않는다. 재시작 뒤 root PUT 의도가 없는 원 의존 업로드는
새 업로드로 재개하지 않으며, root 미전송과 잔여 blob을 구분해 실패 정산한다. SDK context
취소만으로 사용자가 공유 job을 취소했다고 판정하지 않는다. 공유 취소는 원 Run.Cancel을
실제 owner가 확인해야 한다.

게시 I/O가 원 lazy output FD를 사용하는 동안 Close는 종료를 기다린다. 원 output reader와
게시 호출이 끝나고 publication 결과도 정산돼야 작업 공간과 cache 점유를 반환한다.
불명 publication은 정리 요청만으로 성공/실패로 바꾸거나 참조를 반환할 수 없다.
이 내부 native 경계와 연속 Runtime worker·공유 closure/Secret usage 반환의 연결은 구분한다.

`sfcd`의 OCI 게시 client도 기존 BuildSubject의 현재 job/repository 전용 한시 자격을
사용한다. 인증 원문을 journal이나 공개 결과에 넣지 않고 사용 후 폐기한다. 이 client는
프로세스의 시스템 CA 신뢰를 사용하며 registry 인증서는 `sfcd`에서도 신뢰돼야 한다.
Docker Engine에 설치한 CA가 자동으로 `sfcd`의 신뢰로 전달되는 것은 아니다.


원 job이 만료되거나 현재 사용자 권한을 잃어 새 registry token을 얻지 못하는 경우,
원 builder는 authenticated member `image-build-publication-owner`로 정확한 원 출력 태그의
공개 digest 정보만 조회한다. 조회는 현재 quorum의 설치 owner·accepted job·원 registry
namespace에 고정하며 새 push·임의 이미지/본문/Secret 읽기를 허가하지 않는다. 입력/응답은
[SFCP 메시지](../../protocol/sfcp/rules/26-cd.md#원-빌드-게시의-owner-관측)를 따른다.

같은 원 registry의 미종결 running/unknown 빌드가 남으면 listener를 닫고 원 Store·Volume
pin을 정산용으로 보존한다. 실제 process shutdown은 Store/FD를 닫되 원 pin/DB 기록은
유지한다. 재시작 정산은 이미 기록된 lease/consumer와 원 DB를 확인해서 같은 Store만
열며 새 pin·빈 DB·서버를 만들지 않는다. 원 lease/DB가 없거나 namespace가 다르면
불명을 유지한다. 공유 registry closed도 모든 원 빌드 종결 전에는 거부한다.

정산용 read는 registry 상태를 바꾸지 않는다. 원 결과를 확인한 NativeJobs와 Runtime 게시
소비 함수는 같은 원 job에서 이어지며, 연속 worker·최종 shared closure/Secret usage·root
참조 반환의 전체 사용자 경로는 별도 연결/검증 대상이다.


