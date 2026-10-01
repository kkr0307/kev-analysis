import json
from pathlib import Path


# 이 파이썬 파일과 같은 폴더에서 읽고 저장
analysis_dir = Path(__file__).resolve().parent
sample_path = analysis_dir / "nvd_api_sample.json"
result_path = analysis_dir / "nvd_api_published.json"

with open(sample_path, "r", encoding="utf-8") as f:
    data = json.load(f)

# 각 취약점의 공개일만 리스트에 추가
published_dates = []

for item in data["vulnerabilities"]:
    published_dates.append(item["cve"]["published"])

# NVD 날짜는 연-월-일 순서의 같은 형식이므로 문자열로 정렬 가능
# 오래된 날짜부터 최신 날짜 순으로 정렬 (같은 날짜도 그대로 유지)
published_dates.sort()

# 날짜 목록만 JSON으로 저장 
with open(result_path, "w", encoding="utf-8") as f:
    json.dump(published_dates, f, ensure_ascii=False, indent=4)

print(f"공개일 저장 완료: {len(published_dates)}건")
print("파일 위치:", result_path)
