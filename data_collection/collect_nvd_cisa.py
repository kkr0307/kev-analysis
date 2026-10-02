import os
import time
import json
import requests
from dotenv import load_dotenv

# 1. .env 파일 로드 (API 키 안전하게 가져오기)
load_dotenv()
nvd_key = os.getenv("NVD_API_KEY")

def collect_nvd_data():
    print("--- NVD API 데이터 수집 시작 ---")
    headers = {"apiKey": nvd_key} if nvd_key else {}
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    # 조원분 코드 활용: 특정 기간 데이터만 가져와서 테스트 속도 높이기
    params = {
        "lastModStartDate": "2026-09-01T00:00:00.000Z",
        "lastModEndDate": "2026-09-01T01:00:00.000Z"
    }
    
    response = requests.get(url, headers=headers, params=params)
    
    if response.status_code == 200:
        data = response.json()
        cves = data.get("vulnerabilities", [])
        
        # 화면 출력 대신 JSON 파일로 저장 (피드백 반영)
        with open("nvd_original.json", "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
            
        print(f"✅ NVD 원본 저장 완료! (가져온 취약점: {len(cves)}개)")
    else:
        print(f"❌ NVD 수집 실패: HTTP {response.status_code}")

def collect_cisa_kev():
    print("\n--- CISA KEV 데이터 수집 시작 ---")
    kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    
    response = requests.get(kev_url)
    
    if response.status_code == 200:
        data = response.json()
        
        # CISA KEV 원본 데이터 JSON 파일로 저장
        with open("cisa_kev_original.json", "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
            
        print(f"✅ CISA KEV 원본 저장 완료! (총 {data.get('count', 0)}개 취약점)")
    else:
        print(f"❌ CISA KEV 수집 실패: HTTP {response.status_code}")

if __name__ == "__main__":
    # NVD 데이터 수집 실행
    collect_nvd_data()
    
    # 서버 과부하 및 차단 방지를 위해 2초 대기
    time.sleep(2)
    
    # CISA KEV 데이터 수집 실행
    collect_cisa_kev()