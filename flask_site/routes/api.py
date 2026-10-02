from flask import Blueprint, jsonify, request

from analysis import kev_analysis as kev

api_bp = Blueprint("api", __name__, url_prefix="/api")


def _limit_from_request():
    limit = request.args.get("limit", type=int)
    return limit if limit and limit > 0 else None


@api_bp.route("/summary")
def summary():
    return jsonify(kev.get_summary())


@api_bp.route("/trends")
def trends():
    return jsonify(kev.get_trends())


@api_bp.route("/vendors")
def vendors():
    return jsonify(kev.get_vendor_stats(limit=_limit_from_request()))


@api_bp.route("/products")
def products():
    return jsonify(kev.get_product_stats(limit=_limit_from_request()))


@api_bp.route("/cwes")
def cwes():
    return jsonify(kev.get_cwe_stats(limit=_limit_from_request()))


@api_bp.route("/ransomware")
def ransomware():
    return jsonify(kev.get_ransomware_stats())


@api_bp.route("/response-time")
def response_time():
    return jsonify(kev.get_response_time_stats())


@api_bp.route("/filters")
def filters():
    return jsonify(kev.get_filter_options())


@api_bp.route("/vulnerabilities")
def vulnerabilities():
    results = kev.search_vulnerabilities(
        keyword=request.args.get("keyword"),
        vendor=request.args.get("vendor"),
        ransomware=request.args.get("ransomware"),
        year=request.args.get("year"),
    )
    return jsonify({"count": len(results), "results": results})


@api_bp.route("/vulnerabilities/<cve_id>")
def vulnerability_detail(cve_id):
    detail = kev.get_vulnerability_detail(cve_id)
    if detail is None:
        return jsonify({"error": f"CVE '{cve_id}' not found"}), 404
    return jsonify(detail)
