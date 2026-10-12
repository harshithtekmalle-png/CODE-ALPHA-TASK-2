"""
PhishGuard - Real-Time Phishing Detection & Analysis
Flask Application & REST API Server
"""

import os
from flask import Flask, request, jsonify, render_template
import detector
import database

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config["SECRET_KEY"] = os.environ.get("PHISHGUARD_SECRET_KEY", "phishguard-production-secret-key-39182")
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024  # 1MB max request size

# Initialize database schema on startup
database.init_db()


# ---------------------------------------------------------------------------
# Security Headers Middleware
# ---------------------------------------------------------------------------
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# ---------------------------------------------------------------------------
# Web UI Entry Point
# ---------------------------------------------------------------------------
@app.route("/", methods=["GET"])
def index():
    """Render the primary real-time PhishGuard dashboard interface."""
    stats = database.get_dashboard_stats()
    return render_template("index.html", initial_stats=stats)


# ---------------------------------------------------------------------------
# REST API Endpoints
# ---------------------------------------------------------------------------
@app.route("/api/scan-url", methods=["POST"])
def scan_url_api():
    """
    POST /api/scan-url
    Body: {"url": "https://example.com"}
    Analyzes the exact submitted URL, computes transparent risk indicators,
    saves the scan in SQLite, and returns live structured analysis & metrics.
    """
    if not request.is_json:
        return jsonify({
            "success": False,
            "error": "Request body must be valid application/json."
        }), 400

    payload = request.get_json(silent=True) or {}
    raw_url = payload.get("url")

    if raw_url is None:
        return jsonify({
            "success": False,
            "error": "Field 'url' is required."
        }), 400

    if not isinstance(raw_url, str):
        return jsonify({
            "success": False,
            "error": "Field 'url' must be a valid text string."
        }), 400

    cleaned_url = raw_url.strip()
    if not cleaned_url:
        return jsonify({
            "success": False,
            "error": "URL cannot be empty. Please enter a valid URL to analyze."
        }), 400

    if len(cleaned_url) > 2048:
        return jsonify({
            "success": False,
            "error": "URL exceeds maximum permissible length of 2048 characters."
        }), 400

    # Execute rule-based detection engine
    result = detector.analyze_url(cleaned_url)

    # Persist record into SQLite
    saved_record = database.save_scan(
        scan_type="url",
        target=result["target"],
        score=result["score"],
        risk_level=result["risk_level"],
        indicators=result["indicators"],
        explanation=result["explanation"],
        timestamp=result["timestamp"]
    )

    # Fetch live updated database statistics
    updated_stats = database.get_dashboard_stats()

    return jsonify({
        "success": True,
        "data": {
            "id": saved_record["id"],
            "target": result["target"],
            "score": result["score"],
            "risk_level": result["risk_level"],
            "indicators": result["indicators"],
            "explanation": result["explanation"],
            "timestamp": result["timestamp"],
            "scan_type": "url"
        },
        "stats": updated_stats
    }), 200


@app.route("/api/analyze-message", methods=["POST"])
def analyze_message_api():
    """
    POST /api/analyze-message
    Body: {"message": "Urgent: Your account is suspended..."}
    Analyzes the exact submitted message, computes social engineering indicators,
    saves the scan in SQLite, and returns live structured analysis & metrics.
    """
    if not request.is_json:
        return jsonify({
            "success": False,
            "error": "Request body must be valid application/json."
        }), 400

    payload = request.get_json(silent=True) or {}
    raw_msg = payload.get("message")

    if raw_msg is None:
        return jsonify({
            "success": False,
            "error": "Field 'message' is required."
        }), 400

    if not isinstance(raw_msg, str):
        return jsonify({
            "success": False,
            "error": "Field 'message' must be a valid text string."
        }), 400

    cleaned_msg = raw_msg.strip()
    if not cleaned_msg:
        return jsonify({
            "success": False,
            "error": "Message content cannot be empty. Please paste text to analyze."
        }), 400

    if len(cleaned_msg) > 10000:
        return jsonify({
            "success": False,
            "error": "Message exceeds maximum allowed length of 10,000 characters."
        }), 400

    # Execute rule-based detection engine
    result = detector.analyze_message(cleaned_msg)

    # Persist record into SQLite
    saved_record = database.save_scan(
        scan_type="message",
        target=result["target"],
        score=result["score"],
        risk_level=result["risk_level"],
        indicators=result["indicators"],
        explanation=result["explanation"],
        timestamp=result["timestamp"]
    )

    # Fetch live updated database statistics
    updated_stats = database.get_dashboard_stats()

    return jsonify({
        "success": True,
        "data": {
            "id": saved_record["id"],
            "target": result["target"],
            "score": result["score"],
            "risk_level": result["risk_level"],
            "indicators": result["indicators"],
            "explanation": result["explanation"],
            "timestamp": result["timestamp"],
            "scan_type": "message"
        },
        "stats": updated_stats
    }), 200


@app.route("/api/history", methods=["GET"])
def get_history_api():
    """
    GET /api/history
    Retrieve all historical scans from SQLite and latest dashboard statistics.
    """
    limit_param = request.args.get("limit", default=100, type=int)
    if limit_param <= 0 or limit_param > 500:
        limit_param = 100

    history = database.get_history(limit=limit_param)
    stats = database.get_dashboard_stats()

    return jsonify({
        "success": True,
        "history": history,
        "stats": stats
    }), 200


@app.route("/api/history", methods=["DELETE"])
def delete_history_api():
    """
    DELETE /api/history
    Clear all records from SQLite scans table and return reset metrics.
    """
    deleted_count = database.clear_history()
    stats = database.get_dashboard_stats()

    return jsonify({
        "success": True,
        "message": f"Successfully deleted {deleted_count} scan record(s) from database.",
        "deleted_count": deleted_count,
        "stats": stats
    }), 200


@app.route("/api/stats", methods=["GET"])
def get_stats_api():
    """
    GET /api/stats
    Retrieve live real-time metrics calculated directly from SQLite.
    """
    stats = database.get_dashboard_stats()
    return jsonify({
        "success": True,
        "stats": stats
    }), 200


# ---------------------------------------------------------------------------
# Custom Error Handlers
# ---------------------------------------------------------------------------
@app.errorhandler(400)
def handle_bad_request(e):
    return jsonify({
        "success": False,
        "error": "Bad Request: " + str(e.description if hasattr(e, 'description') else "Invalid input syntax")
    }), 400


@app.errorhandler(404)
def handle_not_found(e):
    if request.path.startswith("/api/"):
        return jsonify({
            "success": False,
            "error": "Endpoint not found."
        }), 404
    return render_template("index.html", initial_stats=database.get_dashboard_stats()), 404


@app.errorhandler(405)
def handle_method_not_allowed(e):
    return jsonify({
        "success": False,
        "error": f"Method {request.method} not allowed on this route."
    }), 405


@app.errorhandler(500)
def handle_internal_error(e):
    return jsonify({
        "success": False,
        "error": "An internal server error occurred while processing the scan."
    }), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
