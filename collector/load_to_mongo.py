"""
load_to_mongo.py - 수집한 원본(raw) JSON을 MongoDB에 그대로 적재 (전처리 X)

전처리 담당의 preprocessor.py가 읽는 위치에 맞춰 넣습니다.
  DB: cve_project
    - nvd_raw_data : NVD 원본 (data/nvd_raw/YYYY/nvd_YYYY-MM.json 의 vulnerabilities 항목 하나 = 문서 하나)
    - kev_raw_data : KEV 원본 (cisa_kev_original.json 의 vulnerabilities 항목 하나 = 문서 하나)

실행 방법 (레포 최상위 폴더에서, 수집이 모두 끝난 뒤)
  1) MongoDB 실행 (기본 주소 mongodb://localhost:27017)
  2) pip install pymongo
  3) python collector/load_to_mongo.py
     (다른 주소면 .env에 MONGO_URI="mongodb://..." 추가)

여러 번 실행해도 됩니다: 같은 CVE ID는 덮어쓰기(upsert)라 중복이 생기지 않습니다.
"""

import glob
import json
import os

from pymongo import MongoClient, ReplaceOne

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME = "cve_project"
NVD_GLOB = os.path.join("data", "nvd_raw", "**", "nvd_*.json")
KEV_PATH = "cisa_kev_original.json"
BATCH = 1000                      # 1,000건씩 나눠서 넣기 (메모리/속도)


def upsert_all(collection, docs, key_func):
    """docs를 BATCH 단위로 upsert. key_func(doc) 값이 같은 문서는 덮어씀."""
    ops = []
    for doc in docs:
        doc["_id"] = key_func(doc)                 # CVE ID를 _id로 -> 중복 방지
        ops.append(ReplaceOne({"_id": doc["_id"]}, doc, upsert=True))
        if len(ops) >= BATCH:
            collection.bulk_write(ops, ordered=False)
            ops = []
    if ops:
        collection.bulk_write(ops, ordered=False)


def main():
    try:
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)
        client.admin.command("ping")
    except Exception as e:
        raise SystemExit(f"[오류] MongoDB 연결 실패 ({MONGO_URI}). MongoDB가 켜져 있는지 확인하세요.\n{e}")
    db = client[DB_NAME]

    # 1) NVD: 월별 파일을 하나씩 읽어서 적재
    files = sorted(glob.glob(NVD_GLOB, recursive=True))
    if not files:
        raise SystemExit("[오류] data/nvd_raw/ 에 수집 파일이 없습니다.")
    for path in files:
        try:
            with open(path, encoding="utf-8") as f:
                items = json.load(f).get("vulnerabilities", [])
        except json.JSONDecodeError:
            print(f"  [건너뜀] 읽을 수 없는 파일: {path}")
            continue
        upsert_all(db["nvd_raw_data"], items, lambda d: d["cve"]["id"])
        print(f"  NVD 적재: {os.path.basename(path)} ({len(items):,}건)")

    # 2) KEV
    if os.path.exists(KEV_PATH):
        with open(KEV_PATH, encoding="utf-8") as f:
            kev_items = json.load(f).get("vulnerabilities", [])
        upsert_all(db["kev_raw_data"], kev_items, lambda d: d["cveID"])
        print(f"  KEV 적재: {len(kev_items):,}건")
    else:
        print(f"  [경고] {KEV_PATH} 가 없어 KEV는 건너뜀 (collect_nvd_cisa.py 먼저 실행)")

    print("\n=== MongoDB 적재 결과 ===")
    print(f"  {DB_NAME}.nvd_raw_data : {db['nvd_raw_data'].count_documents({}):,}건")
    print(f"  {DB_NAME}.kev_raw_data : {db['kev_raw_data'].count_documents({}):,}건")


if __name__ == "__main__":
    main()
