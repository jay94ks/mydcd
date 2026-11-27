## User 목적의 서명 관리 operation

D5.04 완료 근거의 User 요청 method=submit/result/resume은 session proof와 `control.UserOperation`을 결합한다. schema1·원 session/At·A1 epoch/request ID·root CAS·typed Change 전체를 session 키로 서명하고 외부 연결 envelope도 현재 challenge로 서명한다. transport를 다시 열어도 원 operation은 바꾸지 않는다. 사용자 key에 Member/Raft/legacy Manage 권한을 부여하지 않는다.

수락 edge는 현재 session·시각/300초 창을 검사하고 replica는 고정 입력 At 및 현재 account/credential/membership/scope를 재검사한다. result는 원 actor/epoch/digest의 retained receipt만 반환하며 found=false는 미실행이 아니다. 자기 session 회수의 원 signed operation은 현재 issuer/account/credential proof와 원 수락 시각을 검증해 일반 session 회수 뒤에도 그 receipt만 조회할 수 있다. 다른 조회/효과나 새 CAS/ID로 바꾸는 허가는 아니다. 새 현재 session의 같은 user는 원 operation/session 서명을 보존해 자기 원 결과만 읽을 수 있다. 다른 user는 시스템 관리자여도 이 경로에서 원 작업을 인수하지 않는다. 현재 client는 명시 not-leader 응답에 한해 고정된 leader pin으로1회 이동하며 전송 후 Unknown에는 재제출하지 않는다.


kind3 relay는 현재 Member만 허용하고 UserAuth만 가진 임시 key는 거부한다. Relay는 Node/Target/Caller/원 Challenge/새 Connection/Signature를 포함한다. cluster와 원 envelope를 같은 서명에 결합해 대상/연결/원 사용자 proof를 대조한다. 수신자는 kind3을 다시 전달하지 않고 challenge/login ticket을 relay로 발급하지 않는다. Reply의 Node/RelayedBy는 진단용이며 권한 근거가 아니다.

resume은 명시 사용자 승인에만 사용한다. 현재 같은 user session/연결/추가 scope를 검사하고 정확한 원 retained receipt가 있으면 반환한다. 부재이면 원 command만 A1에 전달하며 원 credential/issuer/권한·CAS/서명을 그대로 재검사한다. 최초 submit의300초 수락 창과 달리 현재 재승인 session을 요구하고 원 signed At의 원 grant 수명은 유지한다. 다른 actor/ID/CAS로 바꾸거나 원 효과를 자동 재제출하지 않는다.


User enroll-admin은 Session 없이 Enrollment(schema1,원 RequestID,명시 User)와 UserKey=등록 anchor를 담는다. Envelope.Signature는 sfc-admin-enrollment-1 domain·cluster·현재 TLS key·server challenge·정규 body의 Ed25519 proof다. 서버는 지정 anchor·private-key credential·최초 admin 후보/초기 CAS를 검사하고 A1 actor=anchor의 원 module 명령을 동일 FSM에 확정한다. anchor 소비 뒤에는 같은 retained command만 조회하며 일반 node/legacy 권한을 만들지 않는다. member relay로 새 bootstrap proof를 발급하지 않는다. 실제4경계는 잘못된 서명/challenge/TLS key·중복/소비·같은 DB/원 receipt를 확인했다.


