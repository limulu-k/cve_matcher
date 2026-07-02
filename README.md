- 타깃 DB 스키마
    
    ```sql
    SELECT vul_data.id_vul,
        vul_data.title,
        vul_data.file,
        vul_data.function id,
        vul_data.function length,
        vul_data.hash value,
        vul_data.cve_name,
        vul_data.cvss,
        vul_data.detected_counts,
        vul_data.oss_name,
        vul_data.cdb_id,
        vul_data.vul_file,
        vul_data.vul_datacol
    FROM sdb_db.vul_data;
    ```
    

# 1. 파일 전처리 및 git version 정보 수집

- 폴더 구조
    - nvd-json-2.0: nvd 데이터 다운 경로
    - scripts : 실질적 스크립트 저장 위치
    - git : 검색 및 매치 시킬 github 데이터 list 파일들이 존재
    - workspace: 프로그램 실행 중 나오는 중간 파일 및 결과 파일 저장 장소
    - data: nvd 데이터 merge 해놓은 폴더(nvd_merged.json로 저장해 놓음)
    → **`00_merge_json.py`** 사용

## 1-1) ref github link exist case

- github 링크가 존재하는 cve들 필터링
- 없는 경우는 1-2로 토스
- 해당 cve를 필터링하여 github list와 매칭시켜서 별도 파일에 저장
git에 링크 존재 → `step_1_1_ref_github_matched.jsonl`
git에 링크 X → step_1_1_ref_github_unmatched.jsonl

## 1-2) cpe link convert matched case

- cpe에서 vendor;product 를 통해 github 리스트와 매칭
→ `step_1_2_cpe_matched.jsonl`
- 매치 되지 않는 경우 1-3으로 토스

## 1-3) remained case

- 별도의 json 파일로 저장, 추후 분석하여 재사용(지금은 별도의 파일로 저장만 해놓음)
→ `step_1_3_remained.jsonl`

⇒ **`01_splitNpreprocess.py`** 사용

*→ 데이터 분석 및 이전 설계 과정에서 사용되었음
⇒ 다음 DB 구축 과정에서는 그냥 merged.json만 사용함*

## 1-4) workspace/github_cache

- `build_version_cve_db.py`에서 수집
→ db 구축 후 완성 된 db 분석 과정에서 누락된 version 정보들 확인됨
→ 한 10시간 쯤 걸리는 듯
    - DB 1차 구축 이후 cache 재수집 진행하였음

# 2. DB 구축

- DB  목적
    - CVE/NVD baseline 정보
    - CVE와 GitHub repository 연결 정보
    - fix commit과 변경 함수 정보
    - tag/version별 코드 근거 정보
    - 최종 affected/fixed version range
- 최종 목표
    - 깃허브 링크와 버전 정보를 주면 자동으로 CVE가 list up 되는 것
- 진행 과정
    - 1차 DB 구축: **`build_refonly_from_nvd_cache.py`**
        - git 하위에 listup 된 목록과 merged.json  파일 분석하여 github 링크가 ref에 참조 되어 있는것들 workspace/github_cache 에 수집
        - CVE별 references 검사
        - references.url에 `*github.com/owner/repo*` 형태가 직접 있는 CVE만 추출
        - cve_github_refs에 CVE ↔ repo 관계 등록
        → 해당 repo가 github_cache에 있으면 tag/release version 등록
        - NVD CPE range와 GitHub version을 비교
        - version_cve_index 생성
        - 생성 DB 분석
            - 생성된 인스턴스의 갯수 및 1개 이상의 cve가 할당된 레포 갯수 확인
            - cve 매칭된 repo의 version 정보 확인 과정에서 version 자체가 등록되지 않은 경우들을 확인하였음
            → 누락된 cache 재수집
            → 분석했던 데이터 2차 DB 구축 과정에서 날아감
    - git_cache 재수집
        - `02-02_make_ref_repo_fetch_targets.py`
        → DB의 cve_github_refs에 있는 검색 가능 repo만 선별
        - `02-03_fetch_missing_github_cache.py`
        → 선별된 repo 중 cache가 없는 것만 추가 다운로드
    - 2차 DB 구축: **`02-01_build_refonly_from_nvd_cache.py`**
        - 동일한 프로세스 유지, gitcache는 기존에 수집 및 누락된 것 재수집한 데이터 재사용
        - 생성 DB 분석
            - CPE range 없는 CVE는 대부분 NVD 미분석 상태
                - 약 9107개의 cve가 깃허브 repo는 있는데, cpe range가 없음
                → nvd가 affected range를 설정하지 않은 경우임
                ⇒ **직접 들어가서 commit 따져보거나 실험해서 해결해야 함**
            - repo 링크가 있으나 version 정보 등록이 안되있는 경우
                - ref_repos_without_versions = 16410
                - cve가 등재된 제품의 공식 repo가 아닌 reference repo인 경우가 많음
                → version 정보가 없고, 있다고 한들 제품의 공식 repo가 아니기에 의미가 없음
            - `cve_github_refs`에 PoC/reference repo가 많이 들어감
                - ex. rapid7@metasploit-framework 와 같은 경우
                → https://raw.githubusercontent.com/rapid7/metasploit-framework/master/modules/.. 로 등재 되어 있음
                ⇒ 오탐임
                    - 이는 PoC/advisory/exploit repo일 수 있음
                    **→ 위와 같은 경우들 필터링 해야함**
            - 최종적으로 version_cve_index로 완성되지 못하는 경우가 많음
                - GitHub ref repo가 제품 repo가 아니라 PoC/advisory repo임
                - repo는 맞지만 github_versions에 tag/release cache가 없음
                - NVD CPE range는 있지만 GitHub tag 형식과 비교가 안 됨
                - CPE product와 GitHub repo가 의미적으로 연결되지 않음
                - OS/distro CPE range가 섞여 있음
        - **최종 문제**: repo_key 즉, nvd 기반 등록된 repository는 총 20,838개
        하지만 cve 매칭된것은 4428개
        그 중에서도 repo가 raw.githubusercontent.com 인 것은 605개,
        poc/reference/adisory 로 **의심되는 것**은 5,643개임
            
            ⇒ 크게 나누자면 4종류로 나눠짐
            
            - product repo
                - 실제 취약 제품의 공식 repo
                - 예: apache@httpd, vim@vim, python@cpython
            - advisory/reference repo
                - 보안 권고, CVE DB, CSAF, advisory DB
                - 예: cisagov@csaf, rustsec@advisory-db
            - PoC/exploit/report repo
                - PoC, exploit, vulnerability report, 개인 CVE 모음
                - 예: rapid7@metasploit-framework, xxx@poc, xxx@cve
            - 그 외의 경우
                - 오타, 축약,순서 변경
                → 이걸 토큰 유사도로 계산하게 되면 다시 처음 부터 꼬임
                → llm에게 자동으로 들어가서 github 메인 repoo 찾으라 해보는건 어떤가?
                    1. rule-based로 확실한 것 accept/reject
                    2. 애매한 것만 MCP/RAG local LLM에 넘김
                    3. LLM 결과를 GitHub API/package metadata로 검증
                    4. confidence 낮은 건 manual review
                    5. 검증된 repo만 searchable_product_refs에 반영

# 3. query 예제 프로그램

- **`03_query_cves_by_github_version.py`**
    - `--github` 로 링크와 `--version` 으로 버전 정보만 넣어 주면 작동함
    ← 버전 정보는 정규화 과정을 고려하여 v를 붙여넣어고 되고 없애고 넣어도 됨
    - 해당 버전 대에서 발견된 cve 데이터를 가져옴
        
        ex) `python ./scripts/03_query_cves_by_github_version.py --github https://github.com/mongodb/mongo --version 2.6.0`
        

# 99. 리뷰 항목
- 26.07.01
    - 질문
        1. cpe range 없다는게 version range 말씀인지? (version 정보가 아예 없는 경우는 데이터가 없으므로 연구 목적과 다름)
        → 버전 정보가 cpe에 등록되지 않은 경우가 있어서 따로 필터링 했었음
            연구 목적과 다르다면 먼저 해당 케이스 필터링 해도 될듯
        2. 실제 취약 제품의 공식 repo + 그 외 경우 (오타, 축약, 순서 변경) 이렇게 가는 게 좋을 것 같습니다. (PoC나 보안 권고 등은 프로덕트가 아니니까..)
        → centris에서 정확한 매칭 해야할 범위 인지가 필요한듯
    - 일단 github랑 정확히 매칭 + 오타, 축약, 순서변경 등의 케이스부터 고려
    → 프로덕트랑 직접적으로 관련된(HatBOM에서 나오는) 케이스만 필터링 하면 됨
    - 해야할것
        - [ ]  CENTRIS 정리(HatBom)
        - [ ]  Clovery 정리