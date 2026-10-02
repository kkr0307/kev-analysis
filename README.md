# kev-analysis

NVD CVE 데이터와 CISA KEV를 활용하여 취약점의 공개 현황과 실제 악용이 확인된 취약점의 특징을 분석하는 프로젝트입니다.

## 프로젝트 목적

공개되는 취약점의 유형을 파악하고, 그중 실제 악용이 확인된 취약점의 빈도를 파악합니다.
NVD의 취약점 정보에 CISA KEV 등재 여부를 연결하고, 기간별 비교를 통해 근래의 취약점이 어떻게 변화하고 있는지 동향을 분석합니다.

분석에서 확인하려는 질문은 다음과 같습니다.

- 기간별 취약점 공개 건수와 CWE 유형별 비중은 어떻게 달라지는가?
- 분석 대상 중 CISA KEV에 등재된 취약점은 어떤 유형에 분포하는가?


마지막 질문에는 KEV의 `dateAdded` 수집과 과거에 공개된 CVE 정보가 추가로 필요합니다. 세부 분석 기간과 최종 지표는 데이터 검토 후 확정합니다.


## 활용 데이터

| 데이터 | 역할 | 주요 항목 |
| :--- | :--- | :--- |
| NVD CVE API | 취약점의 공개 시점과 유형 확인 | `id`, `published`, `lastModified`, `weaknesses` |
| CISA KEV | 실제 악용이 확인된 취약점 목록과 대조 | `cveID` |

NVD의 `id`와 CISA KEV의 `cveID`를 기준으로 두 데이터를 연결합니다.
CWE는 취약점의 약점 유형을 분류하는 코드입니다.

- [NVD API 공식 문서](https://nvd.nist.gov/developers/vulnerabilities)
- [NVD 응답 JSON 스키마](https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema)
- [CISA KEV 공식 데이터 저장소](https://github.com/cisagov/kev-data)
- [CISA KEV 공식 JSON 스키마](https://github.com/cisagov/kev-data/blob/develop/known_exploited_vulnerabilities_schema.json)

## 현재 구현 상태

| 기능 | 상태 | 내용 |
| :--- | :--- | :--- |
| NVD API 기간 조회 | 구현 | 공개일 조건으로 첫 페이지를 한 번 요청 |
| 원본 JSON 저장 | 구현 | API 응답 구조를 유지하여 저장 |
| 공개일 추출 및 정렬 | 구현 | `published`만 추출하여 오래된 순서로 저장 |
| 분석용 필드 정리 및 KEV 결합 | 구현 | CVE ID, 공개일, 수정일, CWE, KEV 등재 정보 정리 |
| 기간별 비교 및 시각화 | 구현 | 유형별 분포와 기간별 변화 분석 |

## 실행 방법

Python이 설치된 환경에서 저장소를 내려받은 뒤, `README.md`가 있는 프로젝트 폴더에서 실행합니다. 아래 명령은 Windows PowerShell 기준입니다.

### 1. 가상환경과 패키지 준비

가상환경이 없다면 생성합니다.

```powershell
python -m venv venv
```

필요한 패키지를 설치합니다.

```powershell
.\venv\Scripts\python.exe -m pip install -r requirements.txt
```

현재 수집 및 정렬 코드에서 사용하는 주요 라이브러리는 `requests`, `python-dotenv`이며, `json`, `os`, `pathlib`는 Python 기본 라이브러리입니다.

### 2. 환경 변수 설정

프로젝트 최상위 폴더에 `.env` 파일을 만들고 다음과 같이 입력합니다.

```dotenv
NVD_API_KEY=발급받은_API_키
BASE_URL=https://services.nvd.nist.gov/rest/json/cves/2.0
```

현재 코드가 읽는 키 이름은 `NVD_API_KEY`입니다. `BASE_URL`을 비우면 코드의 기본 NVD API 주소를 사용합니다. `.env`는 `.gitignore`에 포함되어 있습니다.

### 3. 조회 기간과 샘플 크기 설정


`analysis/get_nvd_api.py`에서 공개일 범위를 수정합니다. 현재 설정은 2026년 9월이며, `Z`는 UTC 기준을 의미합니다.

```python
start_date = "2026-09-01T00:00:00.000Z"
end_date = "2026-09-30T23:59:59.999Z"
```

한 요청의 날짜 범위는 최대 120일입니다. 현재 `params`의 `resultsPerPage`는 `2000`, `startIndex`는 `0`으로 설정되어 있습니다. 10건만 살펴보려면 `resultsPerPage`를 `10`으로 변경합니다.

**현재 수집 코드는 첫 페이지 한 번만 요청합니다.** 응답의 `totalResults`가 실제로 받은 `vulnerabilities` 목록의 길이보다 크면, 해당 기간의 결과가 더 남아 있는 상태입니다. 전체 동향 분석 전에는 모든 페이지를 수집해야 합니다.

### 4. NVD 샘플 수집

```powershell
.\venv\Scripts\python.exe .\analysis\get_nvd_api.py
```

원본 응답을 `analysis/nvd_api_sample.json`에 저장합니다.

### 5. 공개일 추출 및 정렬

```powershell
.\venv\Scripts\python.exe .\analysis\analysis_api_sample.py
```

샘플의 각 CVE에서 `published`를 추출하여 `analysis/nvd_api_published.json`에 오래된 날짜부터 저장합니다. 같은 공개일이 여러 번 나오면 그대로 유지합니다.

두 스크립트는 재실행 시 각 결과 파일을 덮어씁니다. 저장 위치는 스크립트가 있는 `analysis` 폴더입니다.

## 프로젝트 구조

```text
kev-analysis/
├── data_collection/    # NVD / CISA KEV 데이터 수집
├── preprocessing/      # 데이터 전처리
├── data_analysis/      # 통계 및 분석
├── visualization/      # 분석 결과 시각화
├── flask_site/         # Flask 기반 웹 대시보드
├── dev/                # 개발 및 테스트 코드
└── README.md
```

## 전체 데이터 처리 흐름

**분석 기간 및 수집 범위 확정**  
↓  
**NVD / KEV 원본 데이터 수집**  
↓  
**필드 추출 및 결측값 확인**  
↓  
**CVE ID 기준 데이터 연결**  
↓  
**기간별 / 유형별 집계**  
↓  
**그래프 작성 및 결과 해석**  
↓  
**Flask 시각화**

## 분석 결과

### 1. 기간별 취약점 공개 건수

![기간별 취약점 공개 건수](이미지 경로)

기간별 NVD CVE 공개 건수를 비교하여 취약점 공개 추이를 확인합니다.

### 2. CWE 유형별 취약점 분포

![CWE 유형별 취약점 분포](이미지 경로)

CWE 유형별 취약점 분포를 비교하여 어떤 유형의 취약점이 많이 나타나는지 확인합니다.

### 3. KEV 등재 취약점의 CWE 분포

![KEV 등재 취약점의 CWE 분포](이미지 경로)

CISA KEV에 등재된 CVE를 대상으로 CWE 유형별 분포를 비교합니다.

## Flask 대시보드

분석 결과를 Flask 기반 웹 화면에서 확인할 수 있도록 구성하였습니다.

<img width="945" height="907" alt="image" src="https://github.com/user-attachments/assets/5b9f61fa-8899-4248-a2b2-7182254cf899" />


주요 분석 결과와 시각화 자료를 웹 화면에서 확인할 수 있습니다.

## 주요 결과

- 연간 CVE는 23년부터 26년까지 약 2.4배 증가
- 원격 네트워크 공격 기능이 대다수를 차지
- 험도 점수로는 medium-high 등급이 대부분
 
## 인사이트 도출
- 제일 잦은 횟수로 사용되었던 CWE-79 취약점(XSS) 방어 체계 모색
- 실시간 자동 파싱/분석/업데이트 Flask 대시보드로 발전 가능성
