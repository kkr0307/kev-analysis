# NVD CVE / CISA KEV 대시보드

## 실행

```bash
python -m venv .venv
.venv\Scripts\activate          # macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
python app.py                   # http://localhost:5000
```

## 사진 넣기

`static/images/charts/<키>.png` 로 넣으면 대시보드의 해당 카드에 보입니다.
덮어쓰면 바로 바뀌고, 파일이 없으면 자리표시자가 뜹니다.

키는 `templates/index.html` 의 `chart_card("키", "제목")` 에 적혀 있습니다.
새 카드를 만들려면 이 줄을 추가하면 됩니다.

## 검색

`/vulnerabilities` 에서 키워드·벤더·랜섬웨어·등록연도로 거릅니다.
키워드는 CVE ID, 벤더, 제품, 취약점명, 설명에서 부분 일치로 찾습니다.
결과는 50건씩 나누어 보여주고, CVE ID를 누르면 상세 페이지로 갑니다.

## 구조

```
app.py       라우트 3개 (대시보드 / 검색 / 상세)
kev.py       JSON 읽기 · 검색
templates/   화면
static/      CSS, 차트 이미지
data/        CISA KEV 카탈로그 JSON
```
