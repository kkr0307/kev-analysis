import os
import pandas as pd
from pymongo import MongoClient
import json

# MongoDB 연결 설정
client = MongoClient("mongodb://localhost:27017/")
db = client["nvd_database"]

# 컬렉션 정의 통일
nvd_collection = db["cves"]
kev_collection = db["kev"]            # KEV 데이터 컬렉션 (필요시 확인)
processed_collection = db["cve_processed"]  # 전처리 결과 저장 컬렉션

# 기존 데이터 중복 적재 방지를 위해 인덱스 생성 (cve_id 기준)
nvd_collection.create_index("cve.id", unique=True)

# 2. JSON 파일들이 들어있는 폴더 경로 설정
json_folder_path = "./json_data_folder"  # 본인의 JSON 파일 폴더 경로로 수정하세요

print("🚀 NVD 데이터 MongoDB 적재 시작...")

if os.path.exists(json_folder_path):
    for filename in os.listdir(json_folder_path):
        if filename.endswith(".json"):
            file_path = os.path.join(json_folder_path, filename)
            print(f"파일 처리 중: {filename}")
            
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    
                # NVD API 2.0 피드 구조 기준 (vulnerabilities 리스트 순회)
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
                            print(f"삽입 에러 ({item.get('cve', {}).get('id', 'unknown')}): {e}")
                    print(f"✅ 완료: {filename} ({len(vulnerabilities)}개 취약점)")
                else:
                    print(f"⚠️ 경고: {filename}에 vulnerabilities 데이터가 없습니다.")
                    
            except Exception as e:
                print(f"❌ 파일 읽기 실패 {filename}: {e}")
    print("🎉 NVD 데이터 적재 완료!")
else:
    print(f"⚠️ 폴더를 찾을 수 없습니다: {json_folder_path}. 경로를 확인해주세요.")


def process_and_save():
    """MongoDB 데이터를 정제 및 결합하여 JSON 및 전처리 DB에 저장"""
    print("MongoDB에서 데이터를 불러와 정제 및 KEV 결합을 시작.")
    nvd_items = list(nvd_collection.find())
    kev_items = list(kev_collection.find())

    if not nvd_items:
        print("전처리할 NVD 데이터가 없습니다. NVD 적재 단계를 확인해 주세요.")
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

        # 필수 분석 항목 구성
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

    # JSON 파일 저장
    json_file = "cve_processed.json"
    df.to_json(json_file, orient="records", force_ascii=False, indent=4)
    print(f"JSON 저장 완료: {json_file}")
    print(df.head())

    # MongoDB 전처리 결과 컬렉션에 적재
    processed_collection.delete_many({})
    processed_collection.insert_many(df.to_dict("records"))
    print("MongoDB 전처리 데이터 저장 완료")


if __name__ == "__main__":
    print("=== 데이터 처리 전체 파이프라인 시작 ===")
    # 1. 파일에서 읽어와 적재하는 과정을 먼저 실행하고 싶다면 주석 해제
    # (이미 적재된 상태라면 아래 process_and_save()만 실행하셔도 됩니다.)
    
    process_and_save()
    print("=== 데이터 처리 전체 파이프라인 완료 ===")