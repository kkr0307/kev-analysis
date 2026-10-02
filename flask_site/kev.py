import json
import os

JSON_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "data", "known_exploited_vulnerabilities.json",
)

SEARCH_FIELDS = ("cveID", "vendorProject", "product", "vulnerabilityName", "shortDescription")

_rows = None


def load():
    """JSON을 한 번만 읽어서 리스트로 듬"""
    global _rows
    if _rows is None:
        with open(JSON_PATH, encoding="utf-8") as f:
            _rows = json.load(f)["vulnerabilities"]
    return _rows


def vendors():
    return sorted({r["vendorProject"] for r in load() if r["vendorProject"]})


def years():
    return sorted({r["dateAdded"][:4] for r in load() if r.get("dateAdded")}, reverse=True)


def search(keyword="", vendor="", ransomware="", year=""):
    rows = load()

    if keyword:
        kw = keyword.lower()
        rows = [r for r in rows if any(kw in r.get(f, "").lower() for f in SEARCH_FIELDS)]
    if vendor:
        rows = [r for r in rows if r["vendorProject"] == vendor]
    if ransomware:
        rows = [r for r in rows if r["knownRansomwareCampaignUse"] == ransomware]
    if year:
        rows = [r for r in rows if r.get("dateAdded", "").startswith(year)]

    return sorted(rows, key=lambda r: r.get("dateAdded", ""), reverse=True)


def find(cve_id):
    for row in load():
        if row["cveID"].lower() == cve_id.lower():
            return row
    return None
