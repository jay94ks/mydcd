## tenant 허용 저장 경로 메시지

User typed method `tenant-storage`는 `Params:{Tenant,Node?,After?}`를 기존 session envelope로 전송한다. 모르는 필드는 거부한다. 응답 `Data`는 `{Index,RootRevision,Revision,Items(최대8행),Next?}`이며 각 행은 `{Node,ID,Generation,Revision,Draining,Allowed,Root:{Cluster,Node,Key,ID,Generation,Path}}`이다. 배열·키 인코딩과 페이지/현재 권한·오류는 [전체 명세](../tenant-storage.md)를 따른다. 등록 root 전체를 읽는 시스템 전용 `node-storage`와 권한이 다르다.

