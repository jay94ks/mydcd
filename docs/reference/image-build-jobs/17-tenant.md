## Tenant 종료의 물리 캐시 회수

일반 job/context/policy 삭제는 재사용 cache bytes를 삭제하지 않는다. 같은 tenant/context/
root/builder의 cache 식별자는 context 재등록에도 유지된다. 물리 namespace 회수는 기존
`begin-tenant-retirement`로 신규 수락을 닫고, 공유 잔여 자원·원 build/maintenance와 실제
Docker 객체·본문/SDK/log I/O가 종료된 tenant owner의 마지막 정산에 연결된다. tenant 종료
후 같은 tenant ID를 새로 생성할 수 없으므로 옛 cache를 새 작업으로 재할당하지 않는다.
Volume·backup 등 보존 데이터는 각각의 명시 삭제/등록 해제 계약을 그대로 따른다.

owner는 기존 member `tenant-retirement-work`와 동일 원 operation/시작 revision·inventory/
owner 지문·현재 적용 index/epoch를 검증하고, 공유 tombstone으로 보존한 원 JobSpec과
로컬 원 완료 기록에서 cache를 선택한다. 정책/context 삭제만으로 이 권한을 만들거나
원 사용자 로그인 만료/회수를 새 사용자 서명으로 우회하지 않는다. 현재 allow-list에서
빠졌어도 보존 build/context를 담당한 설치 member는 원 owner census에 포함한다.

같은 observations DB의 cache 행에 원 source·tenant 종료 의도·root/cache inode를 먼저
저장한다. 미종결/활성 I/O·현재 적용 index보다 앞선 로컬 작업·잘못된 원 lease·삭제 의도
없는 파일 부재·교체된 root/cache는 거부한다. 원 Ready 저장 전의 부분 leaf는 실제 비어
있고 고정 소유권/권한일 때만 회수하며 알 수 없는 본문을 삭제 대상으로 채택하지 않는다.

기존 RootManager의 RecordedPin만 열어 원 cache 경로를 confined unlink하고 부모를 fsync한
뒤, 원 삭제 완료와 root Returning 및 현재 cache 관측 제거를 같은 DB 변경으로 저장한다.
파일 삭제 뒤 DB 실패는 원 inode/삭제 의도로 재개한다. 이후 FD를 닫고 정확한 원 lease를
반환한 다음 native Returned를 저장한다. Return 응답 유실은 같은 원 consumer/lease로
정산하고 새 borrow·파일 재생성을 하지 않는다. 미반환 lease는 끝까지 tenant 종료를 막는다.

물리 회수는 과거 signed job/maintenance 완료를 바꾸지 않는다. cache의 이전 SDK 관측은
현재 cache summary에서 제거하며 실제 관측한 빈 cache로 표시하지 않는다. 더 이상 그
관측이 참조하지 않는 과거 자동 metadata만 별도 반복 기록 회수 조건에 따라 지울 수 있다.
최종 tenant 보고는 실제 회수 뒤 로컬 census를 다시 확인하고 기존 서명/원 CAS로 수행한다.
