from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt


BASE_DIR = Path(__file__).resolve().parent
DATA_FILE = BASE_DIR / "data" / "cve_processed.json"
OUTPUT_DIR = BASE_DIR / "output"

OUTPUT_DIR.mkdir(exist_ok=True)

df = pd.read_json(DATA_FILE)

print("데이터 불러오기 완료!")
print("전체 데이터 개수:", len(df))
print()
print(df.head())

df["published"] = pd.to_datetime(df["published"], errors="coerce")

df = df[df["published"].dt.year.between(2023, 2026)]

df["year"] = df["published"].dt.year

year_counts = df["year"].value_counts().sort_index()

print()
print("연도별 CVE 개수")
print(year_counts)

plt.figure(figsize=(8, 5))

year_counts.plot(kind="bar")

plt.title("CVE Count by Year")
plt.xlabel("Year")
plt.ylabel("Number of CVEs")
plt.xticks(rotation=0)
plt.tight_layout()

plt.savefig(
    OUTPUT_DIR / "yearly_cve_count.png",
    dpi=300,
    bbox_inches="tight"
)

plt.close()

print("연도별 CVE 그래프 저장 완료!")

cwe_data = df[
    (~df["cwe"].isin(["Unknown", "NVD-CWE-noinfo", "NVD-CWE-Other"]))
    & (df["cwe"].notna())
]

cwe_top10 = cwe_data["cwe"].value_counts().head(10)

print()
print("CWE TOP 10")
print(cwe_top10)

plt.figure(figsize=(9, 6))

cwe_top10.sort_values().plot(kind="barh")

plt.title("Top 10 CWE Vulnerabilities")
plt.xlabel("Number of CVEs")
plt.ylabel("CWE")
plt.tight_layout()

plt.savefig(
    OUTPUT_DIR / "cwe_top10.png",
    dpi=300,
    bbox_inches="tight"
)

plt.close()

print("CWE TOP 10 그래프 저장 완료!")

severity_data = df[df["severity"] != "Unknown"]

severity_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
severity_counts = severity_data["severity"].value_counts().reindex(
    severity_order, fill_value=0
)

plt.figure(figsize=(8, 5))

severity_counts.plot(kind="bar")

plt.title("CVE Severity Distribution")
plt.xlabel("Severity")
plt.ylabel("Number of CVEs")
plt.xticks(rotation=0)
plt.tight_layout()

plt.savefig(
    OUTPUT_DIR / "severity_distribution.png",
    dpi=300,
    bbox_inches="tight"
)

plt.close()

print("Severity 분포 그래프 저장 완료!")

attack_data = df[df["attack_vector"] != "Unknown"]

attack_counts = attack_data["attack_vector"].value_counts()

plt.figure(figsize=(8, 5))

attack_counts.plot(kind="bar")

plt.title("Attack Vector Distribution")
plt.xlabel("Attack Vector")
plt.ylabel("Number of CVEs")
plt.xticks(rotation=20)
plt.tight_layout()

plt.savefig(
    OUTPUT_DIR / "attack_vector_distribution.png",
    dpi=300,
    bbox_inches="tight"
)

plt.close()

print("Attack Vector 분포 그래프 저장 완료!")

cvss_data = df[df["cvss_score"] > 0]["cvss_score"]

plt.figure(figsize=(9, 5))

plt.hist(cvss_data, bins=20, edgecolor="black")

plt.title("CVSS Score Distribution")
plt.xlabel("CVSS Score")
plt.ylabel("Number of CVEs")
plt.tight_layout()

plt.savefig(
    OUTPUT_DIR / "cvss_score_distribution.png",
    dpi=300,
    bbox_inches="tight"
)

plt.close()

print("CVSS 점수 분포 그래프 저장 완료!")

monthly_counts = (
    df.groupby(df["published"].dt.to_period("M"))
    .size()
)

monthly_counts.index = monthly_counts.index.astype(str)

plt.figure(figsize=(14, 6))

plt.plot(
    monthly_counts.index,
    monthly_counts.values,
    marker="o",
    markersize=3
)

plt.title("Monthly CVE Trend")
plt.xlabel("Month")
plt.ylabel("Number of CVEs")

plt.xticks(
    range(0, len(monthly_counts), 3),
    monthly_counts.index[::3],
    rotation=45
)

plt.tight_layout()

plt.savefig(
    OUTPUT_DIR / "monthly_cve_trend.png",
    dpi=300,
    bbox_inches="tight"
)

plt.close()

print("월별 CVE 동향 그래프 저장 완료!")

top5_cwe = cwe_data["cwe"].value_counts().head(5).index

cwe_yearly = (
    cwe_data[cwe_data["cwe"].isin(top5_cwe)]
    .groupby(["year", "cwe"])
    .size()
    .unstack(fill_value=0)
)

plt.figure(figsize=(10, 6))

for cwe in cwe_yearly.columns:
    plt.plot(
        cwe_yearly.index,
        cwe_yearly[cwe],
        marker="o",
        label=cwe
    )

plt.title("Yearly Trend of Top 5 CWE")
plt.xlabel("Year")
plt.ylabel("Number of CVEs")
plt.xticks([2023, 2024, 2025, 2026])
plt.legend()
plt.grid(alpha=0.3)
plt.tight_layout()

plt.savefig(
    OUTPUT_DIR / "top5_cwe_yearly_trend.png",
    dpi=300,
    bbox_inches="tight"
)

plt.close()

print("TOP 5 CWE 연도별 추이 그래프 저장 완료!")