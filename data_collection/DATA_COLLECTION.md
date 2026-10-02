# 데이터 수집 (Data Collection)

NVD CVE 데이터와 CISA KEV 데이터를 API로 호출해 **가공하지 않은 원본(raw) 그대로** 저장했습니다.
전처리(CWE 분류, KEV 대조 등)는 이 원본을 읽어서 다음 단계에서 진행합니다.

## 1. 데이터 출처

| 구분 | 메인: NVD CVE | 서브: CISA KEV |
|---|---|---|
| 제공 기관 | 미국 NIST (National Vulnerability Database) | 미국 CISA (Known Exploited Vulnerabilities) |
| 접근 방식 | REST API (CVE API 2.0) | 공식 JSON 피드 다운로드 |
| 주소 | https://services.nvd.nist.gov/rest/json/cves/2.0 | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json |
| 수집 범위 | 공개일(published) 기준 **2023-01 ~ 2026-09** (45개월) | 전체 카탈로그 (버전 2026.09.30) |
| 수집 건수 | **196,463건** | **1,730건** |
| 수집일 | 2026-10-01 | 2026-10-01 |
| 수집 코드 | `collector/collect_nvd.py` | `collect_nvd_cisa.py` |

## 2. 연도별 수집 결과 (NVD)

| 연도 | 수집 월 | CVE 수 | 원본 용량 |
|---|---|---|---|
| 2023 | 12개월 | 30,949 | 424 MB |
| 2024 | 12개월 | 40,704 | 527 MB |
| 2025 | 12개월 | 49,972 | 511 MB |
| 2026 | 9개월 (1~9월) | 74,838 | 725 MB |
| **합계** | **45개월** | **196,463** | **약 2.1 GB** |

- 월별 건수: `data/nvd_raw/published_monthly.csv` (공개일 기준 월별 CVE 수, 시각화용)
- 월별 수집 기록(건수·수집 시각·용량): `data/nvd_raw/_manifest.json`
- 모든 달에서 API가 알려준 전체 건수(`totalResults`)와 저장 건수가 일치함을 확인했습니다.

## 3. 수집 방법

NVD CVE API 2.0의 제약에 맞춰 수집했습니다.

| NVD API 제약 | 처리 방법 |
|---|---|
| 날짜 범위는 한 번에 최대 120일 | 한 달 단위로 나눠서 요청 (`pubStartDate` ~ `pubEndDate`) |
| 요청 1번에 최대 2,000건 | `startIndex`를 2,000씩 늘려가며 반복 요청 |
| 요청 횟수 제한 (API 키 사용 시 30초에 50회) | 요청 사이에 0.7초 대기, API 키는 `.env`로 관리 |
| 서버 오류(503 등) 발생 | 대기 시간을 늘려가며 최대 5번 재시도 |

- **공개일(published) 기준**으로 수집했습니다. 수정일(lastModified) 기준이면 오래된 CVE가 섞이기 때문입니다.
- 한 달치를 다 받으면 바로 파일로 저장합니다. 중간에 끊겨도 저장된 달은 건너뛰고 이어서 받습니다.

## 4. 원본 파일 구조

```
data/nvd_raw/
├── 2023/nvd_2023-01.json ~ nvd_2023-12.json
├── 2024/nvd_2024-01.json ~ nvd_2024-12.json
├── 2025/nvd_2025-01.json ~ nvd_2025-12.json
├── 2026/nvd_2026-01.json ~ nvd_2026-09.json
├── _manifest.json
└── published_monthly.csv
cisa_kev_original.json
```

- 각 월별 파일은 **NVD API 응답과 같은 구조**입니다: `resultsPerPage`, `startIndex`, `totalResults`, `format`, `version`, `timestamp`, `vulnerabilities`
- 원본 JSON(월별 27~136MB, 합계 약 2.1GB)은 GitHub 용량 제한(파일당 100MB) 때문에 **레포에 올리지 않고 드라이브로 공유**합니다.

## 5. 원본 읽는 법 (주요 필드 위치)

`item`은 `data["vulnerabilities"]`의 각 항목입니다.

| 데이터 | NVD JSON 위치 | 비고 |
|---|---|---|
| CVE ID | `item["cve"]["id"]` | |
| 공개일 | `item["cve"]["published"]` | `2026-09-01T01:16:33.137` 형식 → 앞 10자리 사용 |
| 수정일 | `item["cve"]["lastModified"]` | |
| 상태 | `item["cve"]["vulnStatus"]` | `Rejected`(취소된 CVE)는 분석에서 제외 권장 |
| CWE | `item["cve"]["weaknesses"][0]["description"][0]["value"]` | `weaknesses`가 없는 CVE 있음 (2026-09 기준 15.4%) |
| CVSS 점수·위험도 | `item["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"/"baseSeverity"]` | v3.1이 없으면 `cvssMetricV40`, `cvssMetricV30`, `cvssMetricV2` 확인 |
| 공격 경로 | `...["cvssData"]["attackVector"]` | v2는 `accessVector` |
| 제조사·제품 | `item["cve"]["affected"][0]["affectedData"][0]["vendor"/"product"]` | NVD 분석 완료 건은 `configurations`(CPE)에도 있음 |

| 데이터 | KEV JSON 위치 (`item` = `data["vulnerabilities"]`의 각 항목) |
|---|---|
| CVE ID | `item["cveID"]` |
| KEV 등재일 | `item["dateAdded"]` |
| 제조사·제품 | `item["vendorProject"]`, `item["product"]` |
| 랜섬웨어 사용 | `item["knownRansomwareCampaignUse"]` |

## 6. 실행 방법

```bash
pip install requests python-dotenv
# .env.example을 복사해 .env로 이름을 바꾸고 NVD_API_KEY 입력 (키는 Slack 공유)

python collect_nvd_cisa.py                                       # KEV 수집
python collector/collect_nvd.py --start 2023-01 --end 2026-09    # NVD 월별 수집
python collector/load_to_mongo.py                                # (선택) 원본을 MongoDB cve_project에 적재
```

- `load_to_mongo.py`는 원본을 가공 없이 `cve_project.nvd_raw_data`, `cve_project.kev_raw_data`에 넣습니다 (`preprocessor.py`가 읽는 위치).
- `check_fields.py`는 수집 결과 점검용입니다 (결측률, KEV 매칭 건수 등).

## 7. 참고 사항

- 최근에 공개된 CVE일수록 아직 KEV에 등재되지 않았을 수 있어서, 최근 달의 KEV 매칭률이 낮게 나옵니다.
- 최근 CVE는 NVD 분석이 밀려 있어서 CVSS가 제조사 기준(v4.0, Secondary)으로만 있는 경우가 많습니다.
- API 키는 `.env`에만 저장하고 GitHub에는 올리지 않습니다 (`.gitignore`에 포함).
