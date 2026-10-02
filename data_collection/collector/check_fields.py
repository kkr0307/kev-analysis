"""
check_fields.py - 수집한 원본이 '컬럼 명세서'의 필드를 제대로 담고 있는지 점검

실행 방법 (레포 최상위 폴더에서, collect_kev.py / collect_nvd.py 실행 후)
  python collector/check_fields.py              # 점검 결과 출력 + data/collection_report.txt 저장
  python collector/check_fields.py --save-csv   # 명세서 컬럼 CSV(data/nvd_cve.csv)도 함께 저장

필요한 파일
  data/nvd_raw/YYYY/nvd_YYYY-MM.json   (collect_nvd.py 결과, 연도별 폴더)
  data/kev_raw.json               (collect_kev.py 결과)

명세서 경로를 그대로 쓰면 생기는 문제를 여기서 안전하게 처리합니다.
  - weaknesses가 없거나 비어 있는 CVE가 있음 -> [0] 접근 시 KeyError/IndexError로 멈춤
  - published 실제 값은 '2026-09-01T01:16:33.137' 형식 -> 앞 10자리(YYYY-MM-DD)만 사용
  - KEV의 vulnerabilities는 리스트 -> 반복문으로 cveID를 하나씩 꺼내야 함
"""

import argparse
import csv
import glob
import json
import os
from collections import Counter

NVD_GLOB = os.path.join("data", "nvd_raw", "**", "nvd_*.json")   # 연도별 폴더(2023/, 2024/ ...)까지 모두 찾음
KEV_PATH = os.path.join("data", "kev_raw.json")
REPORT_PATH = os.path.join("data", "collection_report.txt")
CSV_PATH = os.path.join("data", "nvd_cve.csv")
SPEC_COLUMNS = ["cve_id", "published", "last_modified", "cwe"]


def first_cwe(cve: dict) -> str:
    """명세서 경로 weaknesses[0].description[0].value를 안전하게 꺼냄. 없으면 빈 문자열."""
    try:
        return cve["weaknesses"][0]["description"][0]["value"]
    except (KeyError, IndexError):
        return ""


def has_cvss(cve: dict) -> bool:
    """CVSS 점수가 하나라도 있는지 (v2, v3.0, v3.1, v4.0 중 아무거나)"""
    metrics = cve.get("metrics", {})
    return any(key.startswith("cvssMetric") and metrics[key] for key in metrics)


def has_product(cve: dict) -> bool:
    """제품 정보가 있는지: NVD 분석 완료면 configurations(CPE), 분석 전이면 affected(제조사 제공)"""
    return bool(cve.get("configurations") or cve.get("affected"))


def pct(part: int, whole: int) -> str:
    return f"{part / whole * 100:.1f}%" if whole else "-"


def main():
    parser = argparse.ArgumentParser(description="수집 데이터 필드 점검")
    parser.add_argument("--save-csv", action="store_true", help="명세서 컬럼 CSV도 저장")
    args = parser.parse_args()

    files = sorted(glob.glob(NVD_GLOB, recursive=True))
    if not files:
        raise SystemExit("[오류] data/nvd_raw/ 에 파일이 없습니다. collect_nvd.py를 먼저 실행하세요.")
    if not os.path.exists(KEV_PATH):
        raise SystemExit("[오류] data/kev_raw.json 이 없습니다. collect_kev.py를 먼저 실행하세요.")

    # 1) NVD 원본 -> 명세서 컬럼 추출 (월별 파일을 하나씩 읽음)
    rows, seen = [], set()
    dup = cvss_cnt = product_cnt = 0
    broken_files = []
    for path in files:
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError:
            broken_files.append(os.path.basename(path))
            continue
        for item in data.get("vulnerabilities", []):
            cve = item["cve"]
            if cve["id"] in seen:
                dup += 1
                continue
            seen.add(cve["id"])
            rows.append({
                "cve_id": cve["id"],
                "published": cve.get("published", "")[:10],
                "last_modified": cve.get("lastModified", "")[:10],
                "cwe": first_cwe(cve),
            })
            cvss_cnt += has_cvss(cve)
            product_cnt += has_product(cve)

    # 2) KEV 원본 -> cveID 목록 (vulnerabilities는 리스트라서 반복문으로 꺼냄)
    with open(KEV_PATH, encoding="utf-8") as f:
        kev = json.load(f)
    kev_ids = {v["cveID"].strip() for v in kev["vulnerabilities"]}
    matched = sum(r["cve_id"] in kev_ids for r in rows)

    # 3) 점검 결과 정리
    n = len(rows)
    no_pub = sum(not r["published"] for r in rows)
    no_mod = sum(not r["last_modified"] for r in rows)
    cwe_empty = sum(not r["cwe"] for r in rows)
    cwe_nvd = sum(r["cwe"].startswith("NVD-CWE-") for r in rows)
    dates = sorted(r["published"] for r in rows if r["published"])
    top_cwe = Counter(r["cwe"] for r in rows if r["cwe"].startswith("CWE-")).most_common(10)

    lines = [
        "=== 수집 데이터 점검 결과 ===",
        f"NVD 파일 {len(files)}개 | CVE {n:,}건 (중복 {dup}건 제외)",
        f"공개일 범위: {dates[0]} ~ {dates[-1]}" if dates else "공개일 범위: -",
        "",
        "[명세서 필드 결측]",
        f"  published     없음: {no_pub:,}건 ({pct(no_pub, n)})",
        f"  last_modified 없음: {no_mod:,}건 ({pct(no_mod, n)})",
        f"  cwe           없음: {cwe_empty:,}건 ({pct(cwe_empty, n)})",
        f"  cwe = NVD-CWE-*   : {cwe_nvd:,}건 ({pct(cwe_nvd, n)})  <- noinfo/Other, 분류 시 '미분류' 처리 필요",
        "",
        "[KEV 대조]",
        f"  KEV 전체: {len(kev_ids):,}건 (카탈로그 버전 {kev.get('catalogVersion')})",
        f"  수집 기간 CVE 중 KEV 등재: {matched:,}건 ({pct(matched, n)})",
        "",
        "[참고: 명세서에 없는 필드 - 위험도별/제품별 분석용]",
        f"  CVSS 점수 있음: {cvss_cnt:,}건 ({pct(cvss_cnt, n)})",
        f"  제품 정보 있음: {product_cnt:,}건 ({pct(product_cnt, n)})",
        "",
        "[CWE Top 10]",
    ] + [f"  {cwe:<10} {cnt:,}" for cwe, cnt in top_cwe]
    if broken_files:
        lines += ["", f"[경고] 읽을 수 없는 파일(저장 중 끊김 추정): {', '.join(broken_files)}",
                  "  -> 해당 월만 collect_nvd.py --overwrite 로 다시 받으세요."]

    report = "\n".join(lines)
    print(report)
    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        f.write(report + "\n")
    print(f"\n-> {REPORT_PATH} 저장 (팀 공유용)")

    # 4) (선택) 명세서 컬럼 CSV 저장 - 엑셀에서 한글 안 깨지게 utf-8-sig
    if args.save_csv:
        with open(CSV_PATH, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=SPEC_COLUMNS)
            writer.writeheader()
            writer.writerows(rows)
        print(f"-> {CSV_PATH} 저장 ({n:,}행)")


if __name__ == "__main__":
    main()
