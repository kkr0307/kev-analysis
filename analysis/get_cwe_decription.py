import requests
from pathlib import Path

cwe_number = 89
url = f"https://cwe-api.mitre.org/api/v1/cwe/weakness/{cwe_number}"

response = requests.get(url, timeout=30)
response.raise_for_status()
data = response.json()

analysis_dir = Path(__file__).resolve().parent
env_path = analysis_dir.parent / ".env"
sample_path = analysis_dir / "nvd_api_sample.json"

