## 입력 자료의 원 root 참조와 tenant 종료

draft/Git stage와 archive는 각각 원 scope/plan digest의 독립 RootManager consumer를
보유한다. 설정 변경 뒤에도 native 원 anchor의 consumer를 사용하며 새 scope의 이름으로
옛 lease를 바꾸지 않는다. tenant 종료 점검은 실제 root journal의 lease와 원 native scope
metadata를 대조해 tenant별로 센다. 다른 tenant의 알려진 pin을 합산하지 않으며, 귀속 없는
pin이나 원 allocation에 필요한 lease 유실을 빈 성공으로 처리하지 않는다. 본문뿐 아니라
실제 FD·참조 반환까지 끝나야 owner가 종료를 보고할 수 있다.

