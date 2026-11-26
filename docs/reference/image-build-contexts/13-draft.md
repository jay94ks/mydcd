## draft 미사용 본문 정리

현재 데이터 수명에서 편집으로 더 이상 쓰지 않는 파일 본문은 owner의 기존 모듈 루프가 정리한다. 완료 파일뿐 아니라 원 Expected보다 draft revision이 커져 확정할 수 없는 편집의 부분 파일도 대상이다. 사용자 명령이나 별도 GC 서버를 추가하지 않는다. 한 pass는 소유 draft 4개, draft당 본문 16개까지 처리하며 다음 pass는 나머지 context로 순환한다. 현재 tree의 모든 동일 digest 참조와 현재 draft revision에서 확정 가능한 미완료 편집의 본문은 유지한다. 대상 파일을 알 수 없는 과거 pending intent나 부분 freeze가 있으면 해당 draft의 본문 정리를 보류한다. 완료 freeze archive/게시 version의 수명과는 독립이다.

원 파일 inode를 확인한 뒤, 폐기 대상 편집의 원 입력/지문을 보존하는 폐기 표시와 삭제 intent를 같은 DB 변경에 기록한다. 이어서 unlink·directory fsync·blob/part metadata 정산을 수행한다. 부분 파일은 기록된 원 inode와 0부터 선언 길이까지의 실제 크기를 확인하며, 크기만으로 완료 파일로 채택하지 않는다. 생성 inode를 기록하지 못한 파일은 추측하여 지우지 않는다. 원 intent 없이 없어진 파일·다른 inode는 정상 정리로 보고하지 않는다. 삭제 뒤 DB 정산 실패는 원 intent로 재개하고 그동안 같은 본문에 대한 새 편집/조각 전송은 PENDING으로 거부해 복구를 막는 새 참조를 만들지 않는다. 정산 후 같은 명시 편집을 다시 시도할 수 있다.

이 미사용 본문 경로는 편집 결과 metadata·draft namespace·원 root pin을 삭제하지 않는다. 완료한 edit/file-seal은 본문 회수 뒤에도 원 결과를 돌려주며 같은 ID로 본문을 재생성하지 않는다. 과거 file-part/file-status의 임시 본문이 계속 남는 것은 보장하지 않는다. 이미 tree에서 지운 내용을 다시 올리려면 현재 권한/Scope/CAS의 새 명시 편집을 사용한다. 삭제된 context/과거 생성 수명은 위 별도 수명 회수 경계를 따르며 미완료 업로드·미게시/부분 archive 전체 정산과 구분한다. 이 동작도 RQ6 마지막 실행 검증 전이다.


