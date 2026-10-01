import os
import pandas as pd
from pymongo import MongoClient
import json
import requests


# MongoDB 연결 설정
client = MongoClient("mongodb://localhost:27017/")
db = client["nvd_database"]

# 📌 컬렉션 정의
nvd_collection = db["cves"]
kev_collection = db["kev"]             # KEV 데이터가 담긴 컬렉션
processed_collection = db["processed_cves"]  # 전처리된 데이터가 담길 컬렉션

def ingest_json_files(json_folder_path):
    """JSON 파일들을 읽어 MongoDB에 적재"""
    nvd_collection.create_index("cve.id", unique=True)
    print("🚀 NVD 데이터 MongoDB 적재 시작...")

    for filename in os.listdir(json_folder_path):
        if filename.endswith(".json"):
            file_path = os.path.join(json_folder_path, filename)
            print(f"파일 처리 중: {filename}")
            
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    
                vulnerabilities = data.get("vulnerabilities", [])
                
                if vulnerabilities:
                    for item in vulnerabilities:
                        try:
                            nvd_collection.update_one(
                                {"cve.id": item["cve"]["id"]},
                                {"$set": item},
                                upsert=True
                            )
                        except Exception as e:
                            pass # 중복 등의 에러는 무시
                print(f"✅ 완료: {filename} ({len(vulnerabilities)}개 취약점)")
                
            except Exception as e:
                print(f"❌ 파일 읽기 실패 {filename}: {e}")

    print("🎉 모든 NVD 데이터 적재가 성공적으로 끝났습니다!")


def fetch_and_store_kev():
    """CISA KEV 데이터를 수집하여 MongoDB에 저장"""
    kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    print("CISA KEV 데이터 수집 중...")
    response = requests.get(kev_url)

    if response.status_code == 200:
        kev_data = response.json()
        kev_vulnerabilities = kev_data.get("vulnerabilities", [])

        kev_collection.delete_many({})
        if kev_vulnerabilities:
            kev_collection.insert_many(kev_vulnerabilities)
            print(f"성공! CISA KEV 데이터 {len(kev_vulnerabilities)}건이 MongoDB에 적재되었습니다.")
    else:
        print(f"CISA KEV 수집 실패: {response.status_code} - {response.text}")



def process_and_save():
    """MongoDB 데이터를 정제 및 결합하여 JSON 및 전처리 DB에 저장"""
    print("MongoDB에서 데이터를 불러와 정제 및 KEV 결합을 시작합니다...")
    nvd_items = list(nvd_collection.find())
    kev_items = list(kev_collection.find())

    if not nvd_items:
        print("전처리할 NVD 데이터가 없습니다. 먼저 JSON 적재를 확인해 주세요.")
        return

    # KEV 딕셔너리 생성 (cveID 기준)
    kev_dict = {item.get("cveID"): item.get("dateAdded") for item in kev_items if "cveID" in item}

    rows = []
    for item in nvd_items:
        cve = item.get("cve", {})
        cve_id = cve.get("id")

        # 날짜 형식 통일 (YYYY-MM-DD)
        raw_published = cve.get("published")
        published = raw_published.split("T")[0] if raw_published else "Unknown"

        # CWE 카테고리 형식 통일
        cwe = "Unknown"
        weaknesses = cve.get("weaknesses", [])
        if weaknesses:
            desc_list = weaknesses[0].get("description", [])
            if desc_list:
                cwe_val = desc_list[0].get("value", "Unknown")
                cwe = cwe_val.split(":")[0] if ":" in cwe_val else cwe_val

        # CVSS 메트릭 통합 추출 (v3.1, v3.0, v2 대응)
        cvss_score, severity, attack_vector = None, "Unknown", "Unknown"
        metrics = cve.get("metrics", {})
        
        cvss_v3 = metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", [])
        if cvss_v3:
            cvss_data = cvss_v3[0].get("cvssData", {})
            cvss_score = float(cvss_data.get("baseScore", 0.0)) if cvss_data.get("baseScore") is not None else None
            severity = cvss_v3[0].get("baseSeverity") or cvss_data.get("baseSeverity") or "Unknown"
            attack_vector = cvss_data.get("attackVector", "Unknown")
        else:
            cvss_v2 = metrics.get("cvssMetricV2", [])
            if cvss_v2:
                cvss_data = cvss_v2[0].get("cvssData", {})
                cvss_score = float(cvss_data.get("baseScore", 0.0)) if cvss_data.get("baseScore") is not None else None
                severity = cvss_v2[0].get("baseSeverity", "Unknown")
                attack_vector = cvss_data.get("accessVector", "Unknown")

        # KEV 매칭 여부 확인
        is_kev = cve_id in kev_dict

        rows.append({
            "cve_id": cve_id,
            "published": published,
            "cvss_score": cvss_score,
            "severity": severity,
            "cwe": cwe,
            "attack_vector": attack_vector,
            "is_kev": is_kev
        })

    df = pd.DataFrame(rows)

    # 중복값 및 결측값 처리
    df = df.drop_duplicates(subset=["cve_id"])
    df["cvss_score"] = df["cvss_score"].fillna(0.0)
    df["severity"] = df["severity"].fillna("Unknown")
    df["attack_vector"] = df["attack_vector"].fillna("Unknown")

    #  JSON 파일 저장 (시각화 담당자 전달용)
    json_file = "cve_processed.json"
    df.to_json(json_file, orient="records", force_ascii=False, indent=4)
    print(f"📁 JSON 저장 완료: {json_file}")
    print(df.head())

    # MongoDB 전처리 결과 컬렉션에 적재
    processed_collection.delete_many({})
    processed_collection.insert_many(df.to_dict("records"))
    print(" MongoDB 전처리 데이터 저장 완료")


if __name__ == "__main__":
    json_folder_path = "./json_data_folder"  
    ingest_json_files(json_folder_path)
    fetch_and_store_kev()

    print("=== 데이터 전처리 시작 ===")
    process_and_save()
    print("=== 데이터 전처리 완료 ===")

