## 대상 결정과 원 작업 보존

U0에서 전역 `--cluster NAME --tenant NAME`은 Linux user의 로컬 이름을 실제 cluster/tenant ID로 한 번 해석한다. 생략하면 기본 링크를 사용한다. 명시 설정/기본 링크가 깨졌으면 다른 대상으로 fallback하지 않는다. 등록 시 endpoint를 생략하면 `unix:///run/sfcdp.sock`이며, 이미 선택한 프로필의 endpoint는 보존한다. Unix 파일 접근 권한은 원격 계정·tenant 권한을 대신하지 않는다.

현재 기존 명령의 `--tenant`와 전역 tenant 선택을 함께 주면 실제 ID가 같아야 한다. app.yaml/cluster.yaml의 tenant도 같은 규칙을 따른다. 시스템 관리자도 tenant 자원 변경에는 대상을 명시/해석하며 모든 tenant에 암묵적으로 fan-out하지 않는다. 클러스터 범위 명령에 tenant 기본값이 있다고 해서 그 범위가 축소되거나 권한이 확대되지 않는다.

새 제출은 현재 대상·권한·CAS/quorum을 검사한다. `result/status/resume`은 저장된 원 cluster/tenant·계정/signer·operation/request ID·artifact·서명·참조를 사용한다. 기본 링크 변경은 원 작업을 다른 대상으로 옮기지 않는다. 불일치 시 원 프로필을 선택하도록 오류를 내고 자동 재제출하지 않는다. 결과 조회와 명시 재개는 구분하며 수락 성공을 실제 Healthy/종료로 표시하지 않는다.

계정은 login 성공 시 wallet에 저장한 자격에서 선택한다. 전역 `--user USER`는 해당 username을 지정한다. 생략 시 현재 cluster/고정 profile에 저장 계정이1개면 사용하고,2개 이상이면 후보를 안내하는 오류를 내며 원격 요청을 보내지 않는다.0개·없는 명시 사용자·만료/거부는 명시 login/오류이며 다른 계정으로 fallback하지 않는다. profile 기본 username·최근 login은 다중 후보의 우선순위가 아니다. login의 --username/--user와 전역 --user가 충돌하면 요청 전에 거부한다.

