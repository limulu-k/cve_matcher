# 뻘짓

# 1. NVD 다운로드&파일 확인

- 다운로드
    
    ```jsx
    mkdir -p nvd-json-2.0
    cd nvd-json-2.0
    
    for y in $(seq 2002 $(date +%Y)); do
      wget -c "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-${y}.json.gz"
    done
    
    wget -c "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz"
    wget -c "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz"
    ```
    
- 정규식 확인
    - github: `onwer@repo`
    - NVD: `vendor@product`
    - CPE string: `cpe:2.3:<part>:<vendor>:<product>:<version>:…`
- NVD classification
    1. 완전 일치
    2. 구조적 정규화 일치: 대소문자, 하이픈, 언더스코어, 접미사, 단-복수 차이 등
    3. vendor-owner 불일치: vendor-owner 관계는 깨지지만, ref 테이블 참조시 일치하는 경우
        - vendor 명에 추가 접미사로 인한 관계 깨짐 case
            - vendor 명이 전혀 다른 case
    4. product-repo 불일치: product-repo 관계는 깨지지만, ref 테이블 참조시 일치하는 경우
    5. firmware / hardware / device model: 프로젝트와 맞지 않음으로 폐기

- **문제가 생김**
    - criteria 참고 해서 github 들어가니까 ㅈㄴ 이상한게 있음
        - adobe@experience_manager가 버전별로 레포가 다름!!!
        → experience-manager-65.en, experience-manager-65.ko, experience-manager-64, etc,,,
    
    ⇒ 폐기해야하나….
    

- 결국에 주어진 정보는 vendor, product, cpe string임
- git 자체에서도 tag에 release version 정보가 없는 경우가 많음 ex. gnu/binutils
→ git commit을 좀 찾아봐야 할듯?

# 2. cve-git 자동화 match 알고리즘 설계

- 선행연구 알고리즘
    
    
    | 알고리즘 | 특징 | 단점 |
    | --- | --- | --- |
    | KMP (Knuth-Morris-Pratt) 알고리즘 | 패턴 매칭 알고리즘 (부분 문자열 검색) | 정확한 일치만 가
    능 |
    | Levenshtein Distance 알고리즘 | 두 문자열간 (삽입, 삭제, 대체) 횟수 계산 | 토큰 순서 변경에 민감 |
    | Jaccard Similarity | 토큰 집합 기반  | 유사도 오타 감지 X |
- *폐기*
    - **알고리즘 설계**
        1. 정규화
            1. 대소문자 전부 소문자로 처리
        2. 완전일치 케이스 필터링
            1. ref 참조하여 일치하는지 추가 검증
            → 불일치시 경우가 나뉨
                1. 타고 들어가면 같은 경우: 나이스함
                2. 타고 들어가도 다른 경우
                → 
        3. 레퍼런스 참조 →  github 링크 존재 유무 확인
            
            ⇒ 시간 ㅈㄴ 오래걸림! 하나당 최소 8초 쯤 걸리더라 ⇒ 만개면 8만초(20시간 오버임)
            
    - 
    - 궁금한거
        - 파생 제품은 굳이 상관쓸 필요가 없는가?
            - ex) mongodb, mongodb-instance, mongodb-odm
- 생각한것
    1. 단어 토큰화 시켜서 github와 관련된 것들만 필터링을 해보자
        - 4가지 class로 필터링 구분
            - token_candidate → 그냥 바로 사용 가능
            - reference_token_candidate → ref 일치이기 때문에 그냥 사용
            - cpe_exact
            - cpe_alias
    2. 지금까지는 nvd → git으로 했는데 역으로 git → nvd로 매핑 시켜보자!
        - git 정보를 토대로 cpe와 매칭시켜서 json 형태로 저장
        - 완전 일치와 ref 일치는 검증이 필요 없음 그냥 사용하면 됨
            - alias 일치는 ref 기준으로 일일히 확인해 봐야 할듯
            ⇒ 수동 검증 해서 패턴이 잘 맞는거 같으면 그냥 사용 안될거 같으면 다른 방법 고안 필요
        - git 매칭 또는 cve가 매칭되는게 없는 경우 분석 필요