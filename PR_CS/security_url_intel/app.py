"""
Security Analysis & URL Intelligence Generator - Main Flask Application (app.py)
Provides RESTful APIs for OSINT query generation, passive URL analysis, and export.
Automatically launches default browser on execution.
"""

import logging
import os
import sys
import threading
import time
import webbrowser
from datetime import datetime

from flask import Flask, request, jsonify, render_template, make_response
from flask_cors import CORS

from config import (
    APP_NAME,
    APP_VERSION,
    DEFAULT_HOST,
    DEFAULT_PORT,
    DORK_CATEGORIES,
    SEARCH_ENGINES
)
from dork_generator import DorkGenerator
from url_analyzer import URLAnalyzer
from pattern_detector import SuspiciousPatternDetector
from utils import (
    is_valid_domain,
    is_valid_url,
    normalize_domain,
    format_txt_report,
    format_csv_report,
    format_json_report
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("security_url_intel")

# Initialize Flask app
app = Flask(__name__, template_folder="templates", static_folder="static")
CORS(app)

# Engine instances
dork_engine = DorkGenerator()
analyzer_engine = URLAnalyzer()
pattern_engine = SuspiciousPatternDetector()

# Disable static caching in browser
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0


@app.after_request
def add_no_cache_headers(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "-1"
    return response


@app.route("/")
def index():
    """Serves the single-page application interface."""
    return render_template(
        "index.html",
        app_name=APP_NAME,
        app_version=APP_VERSION,
        categories=DORK_CATEGORIES,
        engines=SEARCH_ENGINES
    )


@app.route("/api/health", methods=["GET"])
def health():
    """Returns application health and operational status."""
    return jsonify({
        "success": True,
        "data": {
            "status": "healthy",
            "service": APP_NAME,
            "version": APP_VERSION,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        },
        "error": None
    })


@app.route("/api/dorks", methods=["POST"])
def generate_dorks():
    """
    POST /api/dorks
    Payload: { "domain": str, "categories": list[str], "engine": str, "authorized": bool }
    """
    data = request.get_json(silent=True) or {}

    # Authorization enforcement
    if not data.get("authorized"):
        return jsonify({
            "success": False,
            "data": None,
            "error": "Access Denied: You must acknowledge that you are authorized to assess this target."
        }), 403

    domain_input = data.get("domain", "").strip()
    if not domain_input:
        return jsonify({
            "success": False,
            "data": None,
            "error": "Validation Error: Domain field cannot be empty."
        }), 400

    normalized = normalize_domain(domain_input)
    if not is_valid_domain(normalized):
        return jsonify({
            "success": False,
            "data": None,
            "error": f"Invalid domain format: '{domain_input}'. Please supply a standard domain name (e.g., example.com)."
        }), 400

    categories = data.get("categories")
    if categories and not isinstance(categories, list):
        categories = None

    engine = data.get("engine", "google")
    if engine not in SEARCH_ENGINES:
        engine = "google"

    try:
        logger.info("Generating OSINT queries for domain: %s (engine: %s)", normalized, engine)
        result = dork_engine.generate_all_categories(normalized, engine=engine, selected_categories=categories)
        return jsonify({
            "success": True,
            "data": result,
            "error": None
        })
    except Exception as e:
        logger.error("Dork generation failed: %s", str(e), exc_info=True)
        return jsonify({
            "success": False,
            "data": None,
            "error": f"Error generating queries: {str(e)}"
        }), 500


@app.route("/api/analyze", methods=["POST"])
def analyze_url():
    """
    POST /api/analyze
    Payload: { "url": str, "authorized": bool }
    """
    data = request.get_json(silent=True) or {}

    # Authorization enforcement
    if not data.get("authorized"):
        return jsonify({
            "success": False,
            "data": None,
            "error": "Access Denied: You must acknowledge that you are authorized to assess this target."
        }), 403

    raw_url = data.get("url", "").strip()
    if not raw_url:
        return jsonify({
            "success": False,
            "data": None,
            "error": "Validation Error: URL field cannot be empty."
        }), 400

    # Auto-prefix https if scheme omitted for validation
    check_url = raw_url if "://" in raw_url else f"https://{raw_url}"
    if not is_valid_url(check_url):
        return jsonify({
            "success": False,
            "data": None,
            "error": f"Invalid URL format: '{raw_url}'. Please enter a valid URL."
        }), 400

    try:
        logger.info("Performing passive analysis on URL: %s", check_url)
        analysis_data = analyzer_engine.analyze(check_url)
        pattern_data = pattern_engine.evaluate(analysis_data)

        # Merge results into cohesive payload
        response_payload = {
            "url": analysis_data["url"],
            "structure": analysis_data["structure"],
            "domain_details": analysis_data["domain_details"],
            "redirects": analysis_data["redirects"],
            "risk": {
                "score": pattern_data["score"],
                "safety_score": pattern_data.get("safety_score", max(0, 100 - pattern_data["score"])),
                "level": pattern_data["level"],
                "summary": pattern_data["summary"]
            },
            "flags": pattern_data["flags"],
            "flag_count": pattern_data["flag_count"],
            "analyzed_at": datetime.utcnow().isoformat() + "Z"
        }

        return jsonify({
            "success": True,
            "data": response_payload,
            "error": None
        })
    except Exception as e:
        logger.error("URL Analysis failed: %s", str(e), exc_info=True)
        return jsonify({
            "success": False,
            "data": None,
            "error": f"Analysis encountered an error: {str(e)}"
        }), 500


@app.route("/api/export", methods=["POST"])
def export_report():
    """
    POST /api/export
    Payload: { "type": "txt"|"csv"|"json", "data": dict, "report_type": "analysis"|"dorks", "authorized": bool }
    """
    data = request.get_json(silent=True) or {}

    if not data.get("authorized"):
        return jsonify({
            "success": False,
            "data": None,
            "error": "Access Denied: Authorization required."
        }), 403

    export_format = (data.get("type") or "txt").lower()
    report_data = data.get("data")
    report_type = data.get("report_type", "analysis")

    if not report_data or not isinstance(report_data, dict):
        return jsonify({
            "success": False,
            "data": None,
            "error": "Validation Error: No valid report data provided to export."
        }), 400

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    if export_format == "json":
        content = format_json_report(report_data)
        filename = f"security_intel_{report_type}_{timestamp}.json"
        mimetype = "application/json"
    elif export_format == "csv":
        content = format_csv_report(report_data, report_type=report_type)
        filename = f"security_intel_{report_type}_{timestamp}.csv"
        mimetype = "text/csv"
    else:  # default to txt
        content = format_txt_report(report_data, report_type=report_type)
        filename = f"security_intel_{report_type}_{timestamp}.txt"
        mimetype = "text/plain"

    response = make_response(content)
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    response.headers["Content-Type"] = f"{mimetype}; charset=utf-8"
    return response


# Global error handlers
@app.errorhandler(400)
def handle_bad_request(e):
    return jsonify({"success": False, "data": None, "error": "Bad Request"}), 400


@app.errorhandler(404)
def handle_not_found(e):
    return jsonify({"success": False, "data": None, "error": "Resource Not Found"}), 404


@app.errorhandler(405)
def handle_method_not_allowed(e):
    return jsonify({"success": False, "data": None, "error": "Method Not Allowed"}), 405


@app.errorhandler(500)
def handle_server_error(e):
    return jsonify({"success": False, "data": None, "error": "Internal Server Error"}), 500


def open_browser():
    """Background helper to launch browser after short start-up delay."""
    time.sleep(1.2)
    url = f"http://{DEFAULT_HOST}:{DEFAULT_PORT}"
    logger.info("Opening web browser at %s", url)
    try:
        webbrowser.open(url)
    except Exception as e:
        logger.warning("Could not launch browser automatically: %s", str(e))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", DEFAULT_PORT))
    host = os.environ.get("HOST", DEFAULT_HOST)

    print("\n" + "=" * 70)
    print(f"  {APP_NAME} v{APP_VERSION}")
    print(f"  Running on: http://{host}:{port}")
    print("  Mode: Authorized Cybersecurity Research & URL Intelligence")
    print("=" * 70 + "\n")

    # Launch browser in a background daemon thread
    if not os.environ.get("WERKZEUG_RUN_MAIN"):  # Avoid duplicate browser tab in Flask reload
        threading.Thread(target=open_browser, daemon=True).start()

    app.run(host=host, port=port, debug=False)

