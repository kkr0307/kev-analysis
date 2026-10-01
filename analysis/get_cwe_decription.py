import requests
from pathlib import Path
import json

cwe_number = 89
url = f"https://cwe-api.mitre.org/api/v1/cwe/weakness/{cwe_number}"

response = requests.get(url, timeout=30)
response.raise_for_status()
data = response.json()

analysis_dir = Path(__file__).resolve().parent
env_path = analysis_dir.parent / ".env"
data_path = analysis_dir / "cwe_api.json"

with open(data_path, "w", encoding="utf-8") as f:
    json.dump(data, f, ensure_ascii=False, indent=4)
    