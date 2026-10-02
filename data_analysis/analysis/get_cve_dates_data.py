from pathlib import Path
import json

'''
    CVE-Recent, CVE-Modified가 공식문서에 나왔듯 
    8일 내로 공개 / 수정된 취약점인지 확인하기 위함. (공식문서 설명이 애매)
    취약점 리스트에서 가장 오래된 published (공개일) 값을 확인
'''

analysis_dir = Path(__file__).resolve().parent

# CVE-Recent.json
data_set =  analysis_dir / "nvdcve-2.0-recent.json"

with open(data_set, "r", encoding="utf-8") as f:
    file_data = json.load(f)
    vuln_list = file_data["vulnerabilities"]


vuln_list.sort(key=lambda item: item["cve"]["published"])

oldest_cve = vuln_list[0]["cve"]

# 가장 오래된 공개일 찾기
print("CVE ID:", oldest_cve["id"])
print("공개일:", oldest_cve["published"])


# CVE-Modified.json
data_set =  analysis_dir / "nvdcve-2.0-modified.json"

with open(data_set, "r", encoding="utf-8") as f:
    file_data = json.load(f)
    vuln_list = file_data["vulnerabilities"]

vuln_list.sort(key=lambda item: item["cve"]["published"])
oldest_published_cve = vuln_list[0]["cve"]

vuln_list.sort(key=lambda item: item["cve"]["lastModified"])
oldest_modified_cve = vuln_list[0]["cve"]

# 가장 오래된 공개일 찾기
print("가장 오래전에 공개된 CVE ID:", oldest_published_cve["id"])
print("공개일:", oldest_modified_cve["published"])
print("가장 오래전에 수정된 CVE ID:", oldest_published_cve["id"])
print("수정일:", oldest_modified_cve["lastModified"])