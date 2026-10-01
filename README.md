# CISA KEV Dashboard (Flask)

CISA(KEV) 카탈로그를 pandas로 가공해 KPI/집계/검색 JSON API로 제공하고, 대시보드/검색
목록/CVE 상세 페이지를 렌더링합니다.

**대시보드의 차트/시각화 영역은 의도적으로 빈 틀입니다.** `static/images/charts/`에
정해진 이름의 PNG 파일을 넣기만 하면 해당 카드에 바로 표시됩니다 (아래 "새 차트나
이미지 추가하기" 참고). 아직 파일이 없는 카드는 참고용으로 `/api/...` 엔드포인트
안내를 보여줍니다 (아래 API 표 참고).

## 실행 방법 (데스크탑)

```bash
python -m venv .venv
source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
python app.py   # http://localhost:5000
```

## 새 차트나 이미지 추가하기

`static/images/charts/` 폴더에 `i1.png` ~ `i6.png` 중 원하는 파일을 넣으면
해당 카드에 그대로 표시됩니다. 파일이 없는 키는 자리표시자가 보입니다.

| 키 | 카드 |
|---|---|
| `i1` | `i1` |
| `i2` | `i2` |
| `i3` |`i3` |
| `i4` | `i4` |
| `i5` | `i5` |
| `i6` |`i6` |

카드 순서를 바꾸려면 `templates/index.html`에서 `chart_card(...)` /
`chart_card_wide(...)` 호출 줄의 순서를 바꾸면 됩니다.

### (선택) matplotlib으로 PNG 만들기

`analysis/visualize.py`에 matplotlib figure를 반환하는 함수를 추가하고
`CHARTS` 딕셔너리에 `"i2": 함수`처럼 등록한 뒤 실행하면 PNG로 저장됩니다.

```bash
python scripts/generate_charts.py
```

### 자바스크립트로 직접 그리기

`index.html`의 `.chart-placeholder`를 `<canvas>`로 바꾸고,
`dashboard.js`에서 `/api/...` 데이터를 받아 차트 라이브러리로 그리면 됩니다.


## 데이터 소스: JSON 기본 + MongoDB 폴백

`.env`의 `DATA_SOURCE`로 제어합니다.

- `json` (기본값) — `data/known_exploited_vulnerabilities.json`(경로는 `KEV_JSON_PATH`로 조정 가능)에서 읽습니다.
  이 파일은 [CISA KEV 카탈로그 JSON](https://github.com/cisagov/kev-data/blob/develop/known_exploited_vulnerabilities.json)과 동일한 형식(`{"vulnerabilities": [...]}`)입니다.
  **JSON 파일이 없거나 비어 있으면 자동으로 MongoDB(`MONGO_URI`/`MONGO_DB`/`MONGO_COLLECTION`)로 폴백**합니다.
- `mongo` — MongoDB만 사용하도록 강제합니다.

MongoDB를 쓰려면 먼저 JSON을 한 번 적재하세요:

```bash
python scripts/import_to_mongo.py
```

어느 쪽이든 `analysis/kev_analysis.py`가 원본 행을 pandas DataFrame으로 읽어 동일한
파생 컬럼(`responseDays`, `year`, `month`, `ransomwareFlag`, `cweCount` 등)을 만들기
때문에, API 응답은 데이터 소스와 무관하게 동일합니다.

## 프로젝트 구조

```
app.py                       Flask 앱 생성/실행 엔트리포인트
config.py                    DATA_SOURCE / JSON / Mongo 설정
analysis/kev_analysis.py     JSON 또는 MongoDB 로딩, 전처리, 집계, 검색 로직
analysis/visualize.py        (선택) matplotlib으로 차트 PNG를 그리는 함수들
routes/main.py                페이지 라우트 (/, /vulnerabilities, /vulnerability/<cve>) · static/images/charts/ 스캔
routes/api.py                JSON API 라우트 (/api/...)
scripts/import_to_mongo.py   JSON을 MongoDB로 적재하는 스크립트
scripts/generate_charts.py   (선택) visualize.py의 CHARTS를 PNG로 저장하는 스크립트
templates/                   index.html, vulnerabilities.html, detail.html (+ base.html)
static/css/style.css
static/js/dashboard.js         대시보드 KPI 숫자만 채움 (차트는 빈 틀)
static/js/vulnerabilities.js   검색 / 필터 / 페이지네이션 테이블
static/js/detail.js            CVE 상세 렌더링
static/images/charts/<키>.png  대시보드 차트 카드에 쓸 이미지 (없으면 자리표시자)
data/known_exploited_vulnerabilities.json  CISA KEV 카탈로그 원본
```

## API

| 엔드포인트 | 설명 |
|---|---|
| `GET /api/summary` | KPI 합계 (전체/벤더/제품/랜섬웨어/평균 대응기간) |
| `GET /api/trends` | 월별 KEV 등록 건수 |
| `GET /api/vendors?limit=10` | 벤더별 CVE 건수 상위 N |
| `GET /api/products?limit=10` | 제품별 CVE 건수 상위 N |
| `GET /api/cwes?limit=10` | CWE별 CVE 건수 상위 N |
| `GET /api/ransomware` | Known / Unknown 랜섬웨어 연관 건수 |
| `GET /api/response-time` | 대응기간(dueDate - dateAdded) 구간별 분포 |
| `GET /api/filters` | 검색 페이지 드롭다운용 벤더/연도 목록 |
| `GET /api/vulnerabilities?keyword=&vendor=&ransomware=&year=` | 검색/필터 |
| `GET /api/vulnerabilities/<cveID>` | CVE 상세 (없으면 404) |
