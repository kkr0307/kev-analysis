# kev-analysis

NVD CVE 데이터와 CISA KEV를 활용하여 취약점의 공개 현황과 실제 악용이 확인된 취약점의 특징을 분석하는 프로젝트입니다.

## 프로젝트 목적

공개되는 취약점의 유형을 파악하고, 그중 실제 악용이 확인된 취약점의 빈도를 파악합니다.
NVD의 취약점 정보에 CISA KEV 등재 여부를 연결하고, 기간별 비교를 통해 근래의 취약점이 어떻게 변화하고 있는지 동향을 분석합니다.

분석에서 확인하려는 질문은 다음과 같습니다.

- 기간별 취약점 공개 건수와 KEV 등재수는 어떻게 변화하는가?

- 분석 대상 중 CISA KEV에 등재된 취약점은 어떤 유형에 분포하는가?

- 근 4년간 공개된 취약점의 위험도는 어느정도인가?

- 자주 이용되는 공격 경로는 어떻게 되는가?

## 활용 데이터

## NVD CVE

| 컬럼명 | NVD JSON 접근 경로 | 데이터 타입 | 설명 및 비고 |
| :--- | :--- | :--- | :--- |
| `cve_id` | `item["cve"]["id"]` | String | CVE 식별자 |
| `published` | `item["cve"]["published"]` | String | 취약점 최초 공개 일시. 전처리 과정에서 `YYYY-MM-DD` 형식으로 변환 |
| `cwe` | `item["cve"]["weaknesses"][0]["description"][0]["value"]` | String | CWE 유형 코드. 예: `CWE-89` |
| `cvss_score` | CVSS v3.1: `item["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]`<br>CVSS v3.0: `item["cve"]["metrics"]["cvssMetricV30"][0]["cvssData"]["baseScore"]`<br>CVSS v2: `item["cve"]["metrics"]["cvssMetricV2"][0]["cvssData"]["baseScore"]` | Float | 취약점 자체의 기술적 심각도를 0.0~10.0 범위의 점수로 표현 |
| `severity` | CVSS v3.1: `item["cve"]["metrics"]["cvssMetricV31"][0]["baseSeverity"]`<br>CVSS v3.0: `item["cve"]["metrics"]["cvssMetricV30"][0]["baseSeverity"]`<br>CVSS v2: `item["cve"]["metrics"]["cvssMetricV2"][0]["baseSeverity"]` | String | CVSS 심각도 등급. `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` 등의 값 |
| `attack_vector` | CVSS v3.1: `item["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["attackVector"]`<br>CVSS v3.0: `item["cve"]["metrics"]["cvssMetricV30"][0]["cvssData"]["attackVector"]`<br>CVSS v2: `item["cve"]["metrics"]["cvssMetricV2"][0]["cvssData"]["accessVector"]` | String | 취약점 악용에 필요한 공격 접근 경로 |

## CISA KEV

| 컬럼명 | CISA KEV JSON 접근 경로 | 데이터 타입 | 설명 및 비고 |
| :--- | :--- | :--- | :--- |
| `cve_id` | `item["vulnerabilities"][...]["cveID"]` | String | 실제 악용이 확인되어 KEV에 등재된 취약점의 CVE 식별자 |

NVD의 `id`와 CISA KEV의 `cveID`를 기준으로 두 데이터를 연결합니다.
CWE는 취약점의 약점 유형을 분류하는 코드입니다.

- [NVD API 공식 문서](https://nvd.nist.gov/developers/vulnerabilities)
- [NVD 응답 JSON 스키마](https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema)
- [CISA KEV 공식 데이터 저장소](https://github.com/cisagov/kev-data)
- [CISA KEV 공식 JSON 스키마](https://github.com/cisagov/kev-data/blob/develop/known_exploited_vulnerabilities_schema.json)

현재 수집 및 정렬 코드에서 사용하는 주요 라이브러리는 `requests`, `python-dotenv`이며, `json`, `os`, `pathlib`는 Python 기본 라이브러리입니다.

### 2. 환경 변수 설정

프로젝트 최상위 폴더에 `.env` 파일을 만들고 다음과 같이 입력합니다.

```dotenv
NVD_API_KEY=발급받은_API_키
BASE_URL=https://services.nvd.nist.gov/rest/json/cves/2.0
```

현재 코드가 읽는 키 이름은 `NVD_API_KEY`입니다. `BASE_URL`을 비우면 코드의 기본 NVD API 주소를 사용합니다. `.env`는 `.gitignore`에 포함되어 있습니다.

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

<img width="1042" height="641" alt="CVE Count by Year" src="https://github.com/user-attachments/assets/07bae158-9f5c-4c9c-b861-0099e3737344" />

기간별 NVD CVE 공개 건수를 비교하여 취약점 공개 추이를 확인하여 매년 증가하고 있는 추세를 확인하였습니다. 

### 2. CWE 유형별 취약점 분포

<img width="975" height="642" alt="cwe_top10" src="https://github.com/user-attachments/assets/95cea907-f769-4585-abb7-4be0fe5ae5e4" />

CISA KEV에 등재된 CVE를 대상으로 CWE 유형별 분포를 비교한 결과 CVE-79가 가장 많은 공격에 사용되었다는 결과를 도출할 수 있었습니다. 

### 3. CVE 위험도 점수 분포

<img width="1041" height="647" alt="CVE Severity Distribution" src="https://github.com/user-attachments/assets/4af26173-40b8-44b2-994e-fd84d2d6e74e" />

대부분의 공격이 MEDIUM-HIGH 점수에 분포하고 있는 것을 확인했습니다.

## Flask 대시보드

분석 결과를 Flask 기반 웹 화면에서 확인할 수 있도록 구성하였습니다.

<img width="945" height="907" alt="image" src="https://github.com/user-attachments/assets/5b9f61fa-8899-4248-a2b2-7182254cf899" />
<img width="1061" height="907" alt="2" src="https://github.com/user-attachments/assets/ead6f870-1817-4eec-a2d4-eee18ccf06ae" />
<img width="945" height="907" alt="3" src="https://github.com/user-attachments/assets/ebb30849-7c86-4e4a-be9f-2980da0f04da" />

주요 분석 결과와 시각화 자료를 웹 화면에서 확인할 수 있습니다.

## 주요 결과

- 연간 CVE는 23년부터 26년까지 약 2.4배 증가
- 원격 네트워크 공격 기능이 대다수를 차지
- 험도 점수로는 medium-high 등급이 대부분
 
## 인사이트 도출
- 제일 잦은 횟수로 사용되었던 CWE-79 취약점(XSS) 방어 체계 모색
- 실시간 자동 파싱/분석/업데이트 Flask 대시보드로 발전 가능성
