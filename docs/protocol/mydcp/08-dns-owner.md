## 관리 DNS의 원 owner 보고

관리 DNS의 설치 owner 보고는 기존 Management request의 `network-dns-progress` method를 사용한다. schema1 `NetworkDNSProgress`의 `Kind=network-dns`, cluster/reporter·정확한 정책 source generation/revision·Apps root CAS·공유 network revision·module epoch·전체 view digest를 `mydc-network-dns-progress-1` 도메인으로 서명한다. 서버가 현재 설치 member/보고자 일치를 확인하고 같은 과반수/FSM 경로에서 설정을 다시 파생한다. 이 보고는 app 소유권이나 native Ready를 부여하지 않는다. 설정 보고는 시계를 넣지 않으며 동일 원 command digest로 수신 불명/경쟁을 대조한다. optional `Close/At`은 원 consumer/lifetime·주소 fence 또는 전체 instance의 별도 signed 종료 증거와 수신 시각 검사를 요구한다. wire 목적/별도 TCP/새 schema 번호를 추가하지 않는다. 정책/실제 소비 경계는 관리 DNS 계약을 따른다.

<a id="후속-동적-node-admission회수"></a>

