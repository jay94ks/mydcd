## 폐기된 설정의 미완료 freeze 정리

완료 archive scope가 아직 없는 원 freeze는 입력 파일의 회수 방지 참조를 유지한다.
현재 설정 revision이 같은 동안에는 시계상 만료만으로 이를 지우지 않는다. 기존 owner의
제한된 정리 pass는 최신 quorum 상태에서 context/policy의 단조 revision 증가나 삭제로
원 freeze의 게시가 불가능해졌는지 확인한다. 현재 상태보다 앞선 로컬 scope나 서로 다른
root/생성 수명은 추정해 삭제하지 않는다.

회수는 원 freeze 기록에 삭제 의도를 먼저 저장하고 정확한 원 inode를 unlink/fsync한 뒤
완료 표시를 남긴다. 저장 중단 뒤에는 같은 의도로 정산하며 같은 freeze ID를 재생성하지
않는다. 교체 파일·의도 전 파일 부재·원 archive header와의 모순·열린 draft descriptor는
보호한다. 실제 완료 뒤에만 해당 미완료 freeze가 붙잡던 미사용 본문을 기존 파일 회수로
정리할 수 있다. 현재 tree·원 edit 결과와 완료/채택된 archive는 이 경로의 삭제 대상이 아니다.

이 처리는 새 사용자 명령·session·wire 메시지를 만들지 않는다. 과거 draft 수명과
완료된 미게시 archive의 본문/root pin 정산은 별도 수명 경계이며, 부분 ZIP 회수만으로
tenant의 모든 입력 자료가 반환됐다고 판단하지 않는다.

