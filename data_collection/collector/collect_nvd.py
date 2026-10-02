"""
collect_nvd.py - NVD CVE API 2.0 기간별 수집 (데이터 수집 담당, 메인 데이터셋)

실행 방법
  1) pip install requests python-dotenv
  2) 실행 위치(레포 최상위 폴더)에 .env 파일을 두고 아래 한 줄 작성
       NVD_API_KEY="발급받은키"
  3) 레포 최상위 폴더에서:
       python collector/collect_nvd.py --start 2023-01 --end 2026-09
     테스트:
       python collector/collect_nvd.py --start 2026-09 --end 2026-09

결과물 (연도별 폴더 안에 월별 파일)
  data/nvd_raw/2023/nvd_2023-01.json ... nvd_2023-12.json
  data/nvd_raw/2024/...  data/nvd_raw/2025/...  data/nvd_raw/2026/...
  data/nvd_raw/published_monthly.csv  (공개일 기준 월별 CVE 수, 수집이 끝날 때 자동 생성)
    -> NVD API 응답과 같은 구조: resultsPerPage, startIndex, totalResults, format,
       version, timestamp, vulnerabilities (팀원 샘플 JSON과 동일, 들여쓰기 4칸)
  data/nvd_raw/_manifest.json  (월별 건수, 수집 시각 -> 출처 문서 작성용)

설계 포인트
  - 한 달 단위로 요청: NVD 날짜 범위 제한(최대 120일)을 항상 지킴
  - 한 달에 파일 1개: 1년치를 한 파일에 담으면 수백 MB가 되어 다루기 어려움
  - 이어받기: 이미 받은 달은 건너뜀 (다시 받으려면 --overwrite)
  - 실패 시 재시도, 페이지당 최대 2,000건씩 startIndex로 넘김
"""

import argparse
import calendar
import csv
import json
import os
import time
from datetime import datetime, timezone

import requests

# .env 파일이 있으면 NVD_API_KEY를 자동으로 읽음 (pip install python-dotenv)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000
API_KEY = os.getenv("NVD_API_KEY")
SLEEP_SEC = 0.7 if API_KEY else 6      # 키 있음: 30초에 50회 / 없음: 30초에 5회
OUT_DIR = os.path.join("data", "nvd_raw")
MANIFEST = os.path.join(OUT_DIR, "_manifest.json")
PUBLISHED_CSV = os.path.join(OUT_DIR, "published_monthly.csv")


def request_with_retry(params: dict, max_retry: int = 5) -> dict:
    headers = {"apiKey": API_KEY} if API_KEY else {}
    for attempt in range(1, max_retry + 1):
        try:
            res = requests.get(BASE_URL, params=params, headers=headers, timeout=120)
            if res.status_code == 200:
                return res.json()
            print(f"  [경고] HTTP {res.status_code} (시도 {attempt}/{max_retry})")
            if res.status_code == 404 and attempt == 1:
                print("  -> API 키가 잘못됐거나 활성화되지 않았을 수 있습니다.")
        except requests.RequestException as e:
            print(f"  [경고] 네트워크 오류: {e} (시도 {attempt}/{max_retry})")
        time.sleep(6 * attempt)
    raise RuntimeError(f"요청 실패: {params}")


def month_range(start: str, end: str):
    """'2025-01' ~ '2025-12' -> (2025,1), (2025,2), ..."""
    y, m = map(int, start.split("-"))
    ey, em = map(int, end.split("-"))
    while (y, m) <= (ey, em):
        yield y, m
        y, m = (y + 1, 1) if m == 12 else (y, m + 1)


def collect_month(y: int, m: int) -> list:
    last_day = calendar.monthrange(y, m)[1]
    params = {
        "pubStartDate": f"{y}-{m:02d}-01T00:00:00.000",
        "pubEndDate": f"{y}-{m:02d}-{last_day}T23:59:59.999",
        "resultsPerPage": PAGE_SIZE,
        "startIndex": 0,
    }
    items, first_page = [], None
    while True:
        data = request_with_retry(params)
        if first_page is None:
            first_page = data                  # format/version/timestamp를 그대로 쓰기 위해 보관
        batch = data.get("vulnerabilities", [])
        total = data.get("totalResults", 0)
        items.extend(batch)
        print(f"  {len(items)} / {total}")
        params["startIndex"] += len(batch)
        time.sleep(SLEEP_SEC)
        if params["startIndex"] >= total or not batch:
            break
    # 중복 제거 (CVE ID 기준)
    items = list({it["cve"]["id"]: it for it in items}.values())

    # NVD API 응답과 똑같은 구조로 합치기 (팀원 샘플과 동일한 형식)
    return {
        "resultsPerPage": len(items),
        "startIndex": 0,
        "totalResults": len(items),
        "format": first_page.get("format", "NVD_CVE"),
        "version": first_page.get("version", "2.0"),
        "timestamp": first_page.get("timestamp"),
        "vulnerabilities": items,
    }


def main():
    parser = argparse.ArgumentParser(description="NVD CVE 월별 수집")
    parser.add_argument("--start", required=True, help="시작 월 YYYY-MM")
    parser.add_argument("--end", required=True, help="종료 월 YYYY-MM")
    parser.add_argument("--overwrite", action="store_true", help="이미 받은 달도 다시 받기")
    parser.add_argument("--compact", action="store_true", help="들여쓰기 없이 저장 (용량 절약)")
    args = parser.parse_args()

    os.makedirs(OUT_DIR, exist_ok=True)
    manifest = {}
    if os.path.exists(MANIFEST):
        with open(MANIFEST, encoding="utf-8") as f:
            manifest = json.load(f)

    print(f"API 키: {'사용' if API_KEY else '미사용(느림)'}")
    for y, m in month_range(args.start, args.end):
        tag = f"{y}-{m:02d}"
        year_dir = os.path.join(OUT_DIR, str(y))          # 연도별 폴더
        os.makedirs(year_dir, exist_ok=True)
        path = os.path.join(year_dir, f"nvd_{tag}.json")

        # 예전 버전으로 받은 파일(data/nvd_raw/nvd_YYYY-MM.json)이 있으면 연도 폴더로 옮김
        old_path = os.path.join(OUT_DIR, f"nvd_{tag}.json")
        if os.path.exists(old_path) and not os.path.exists(path):
            os.replace(old_path, path)
            if tag in manifest:
                manifest[tag]["file"] = f"{y}/nvd_{tag}.json"
                with open(MANIFEST, "w", encoding="utf-8") as f:
                    json.dump(dict(sorted(manifest.items())), f, ensure_ascii=False, indent=2)
            print(f"[이동] {old_path} -> {path}")
        if os.path.exists(path) and not args.overwrite:
            print(f"[건너뜀] {tag} (이미 있음)")
            continue

        print(f"[수집] {tag}")
        data = collect_month(y, m)
        count = data["totalResults"]
        collected_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        tmp_path = path + ".tmp"               # 임시 파일에 먼저 저장 -> 저장 중 끊겨도 깨진 파일이 안 남음
        with open(tmp_path, "w", encoding="utf-8") as f:
            # 팀원 샘플처럼 들여쓰기 4칸 (용량을 줄이려면 --compact)
            json.dump(data, f, ensure_ascii=False, indent=None if args.compact else 4)
        os.replace(tmp_path, path)             # 저장이 끝난 뒤에만 정식 파일명으로 변경

        # 수집 기록(출처 문서용)은 데이터 파일이 아니라 _manifest.json에 따로 남김
        size_mb = os.path.getsize(path) / 1024 / 1024
        manifest[tag] = {"count": count, "collected_at": collected_at,
                         "pubStartDate": f"{tag}-01", "endpoint": BASE_URL,
                         "file": os.path.relpath(path, OUT_DIR).replace(os.sep, "/"), "size_mb": round(size_mb, 1)}
        with open(MANIFEST, "w", encoding="utf-8") as f:
            json.dump(dict(sorted(manifest.items())), f, ensure_ascii=False, indent=2)
        print(f"  저장: {path} ({count}건, {size_mb:.1f}MB)")

    # 연도별 합계 출력
    print("\n=== 연도별 수집 현황 ===")
    for year in sorted({k[:4] for k in manifest}):
        months = {k: v for k, v in manifest.items() if k.startswith(year)}
        print(f"  {year}년: {len(months)}개월 / {sum(v['count'] for v in months.values()):,}건")
    total = sum(v["count"] for v in manifest.values())
    print(f"완료. 누적 {len(manifest)}개월 / {total:,}건 -> {OUT_DIR}")

    # 공개일(published) 기준 월별 건수 CSV -> 엑셀/matplotlib로 바로 추이 그래프 가능
    with open(PUBLISHED_CSV, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(["pub_month", "year", "month", "cve_count"])
        for tag, info in sorted(manifest.items()):
            writer.writerow([tag, tag[:4], int(tag[5:]), info["count"]])
    print(f"-> {PUBLISHED_CSV} 저장 (공개일 기준 월별 CVE 수, 시각화용)")


if __name__ == "__main__":
    main()
