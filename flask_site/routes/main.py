import os

from flask import Blueprint, render_template

main_bp = Blueprint("main", __name__)

# static/images/charts/<키>.png 로 저장된 파일이 있으면 그 카드에 그대로
# 보여줍니다. 파일이 없는 키는 템플릿이 자리표시자(placeholder)를 보여줍니다.
CHARTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "static", "images", "charts",
)


def _available_charts():
    if not os.path.isdir(CHARTS_DIR):
        return set()
    return {
        os.path.splitext(name)[0]
        for name in os.listdir(CHARTS_DIR)
        if name.lower().endswith(".png")
    }


@main_bp.route("/")
def index():
    return render_template("index.html", charts=_available_charts())


@main_bp.route("/vulnerabilities")
def vulnerabilities():
    return render_template("vulnerabilities.html")


@main_bp.route("/vulnerability/<cve_id>")
def vulnerability_detail(cve_id):
    return render_template("detail.html", cve_id=cve_id)
