import json
import os
from pathlib import Path

import requests
from dotenv import load_dotenv


# 경로 설정
analysis_dir = Path(__file__).resolve().parent
env_path = analysis_dir.parent / ".env"
sample_path = analysis_dir / "nvd_api_sample.json"

# .env 읽기
load_dotenv(env_path)
API_KEY = os.getenv("NVD_API_KEY")
# .env의 BASE_URL이 비어 있으면 NVD 공식 API 주소 사용
BASE_URL = os.getenv("BASE_URL") or "https://services.nvd.nist.gov/rest/json/cves/2.0"

if not API_KEY:
    raise ValueError("프로젝트 폴더의 .env에 NVD_KEY를 입력하세요.")

# 조회할 공개일 범위 설정
# 지정할 수 있는 범위 120일
# Z는 UTC 시간 기준
start_date = "2026-09-01T00:00:00.000Z"
end_date = "2026-09-30T23:59:59.999Z"

url = BASE_URL
headers = {"apiKey": API_KEY}

# 기간에 해당하는 결과 중 첫 페이지의 최대 10건만 요청
params = {
    "pubStartDate": start_date,
    "pubEndDate": end_date,
    "resultsPerPage": 2000,
    "startIndex": 0,
}

response = requests.get(url, headers=headers, params=params, timeout=60)

if response.status_code != 200:
    print("NVD 응답:", response.headers.get("message", "요청 실패"))

response.raise_for_status()
data = response.json()

with open(sample_path, "w", encoding="utf-8") as f:
    json.dump(data, f, ensure_ascii=False, indent=4)

print(f'샘플 저장 완료: {len(data["vulnerabilities"])}건')
print("파일 위치:", sample_path)
