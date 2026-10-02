import os

from flask import Flask, abort, render_template, request

import kev

app = Flask(__name__)

CHARTS_DIR = os.path.join(app.static_folder, "images", "charts")

PAGE_SIZE = 50


def available_charts():
    """static/images/charts/ 에 있는 PNG의 파일 이름(확장자 제외) 집합.
    templates/index.html 이 이 집합으로 카드를 그릴지 자리표시자를 그릴지 정함"""
    if not os.path.isdir(CHARTS_DIR):
        return set()
    return {
        os.path.splitext(name)[0]
        for name in os.listdir(CHARTS_DIR)
        if name.lower().endswith(".png")
    }


@app.route("/")
def index():
    return render_template("index.html", charts=available_charts())


@app.route("/vulnerabilities")
def vulnerabilities():
    form = {
        "keyword": request.args.get("keyword", "").strip(),
        "vendor": request.args.get("vendor", ""),
        "ransomware": request.args.get("ransomware", ""),
        "year": request.args.get("year", ""),
    }
    results = kev.search(**form)

    pages = max(1, -(-len(results) // PAGE_SIZE))
    page = min(max(1, request.args.get("page", 1, type=int)), pages)
    start = (page - 1) * PAGE_SIZE

    return render_template(
        "vulnerabilities.html",
        rows=results[start:start + PAGE_SIZE],
        count=len(results),
        page=page,
        pages=pages,
        form=form,
        # 페이지 이동 링크에 붙일 검색 조건 (빈값은 제외)
        query={k: v for k, v in form.items() if v},
        vendors=kev.vendors(),
        years=kev.years(),
    )


@app.route("/vulnerability/<cve_id>")
def vulnerability_detail(cve_id):
    row = kev.find(cve_id)
    if row is None:
        abort(404)
    return render_template("detail.html", v=row)


if __name__ == "__main__":
    app.run(debug=True)
