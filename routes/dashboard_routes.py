from flask import Blueprint, render_template, jsonify, request, current_app
from database import DashboardRepository

dashboard_bp = Blueprint("dashboard", __name__)


# ============================================================================
# DASHBOARD UI ROUTE
# ============================================================================

@dashboard_bp.route("/dashboard", methods=["GET"])
def dashboard_view():
    """
    Renders the local administrative Security Monitoring Dashboard.
    Provides visual analytics on XSS attacks detected and prevented.
    """
    current_app.logger.info("Security Monitoring Dashboard accessed.")
    return render_template("dashboard.html")


# ============================================================================
# TELEMETRY API ENDPOINTS (PARSED, PARAMETERIZED & SANITIZED JSON)
# ============================================================================

@dashboard_bp.route("/api/security/summary", methods=["GET"])
def api_summary():
    """Returns high-level metric counts (total, high, critical, blocked)."""
    try:
        time_range = request.args.get("time_range", "all")
        data = DashboardRepository.get_summary(time_range=time_range)
        return jsonify(data), 200
    except Exception as e:
        current_app.logger.error("Error generating summary telemetry: %s", str(e))
        return jsonify({"error": "Unable to retrieve security telemetry."}), 500


@dashboard_bp.route("/api/security/risk-distribution", methods=["GET"])
def api_risk_distribution():
    """Returns aggregated event counts grouped by risk level."""
    try:
        time_range = request.args.get("time_range", "all")
        data = DashboardRepository.get_risk_distribution(time_range=time_range)
        return jsonify(data), 200
    except Exception as e:
        current_app.logger.error("Error generating risk distribution: %s", str(e))
        return jsonify({"error": "Unable to retrieve risk telemetry."}), 500


@dashboard_bp.route("/api/security/actions", methods=["GET"])
def api_action_distribution():
    """Returns aggregated event counts grouped by prevention response action."""
    try:
        time_range = request.args.get("time_range", "all")
        data = DashboardRepository.get_action_distribution(time_range=time_range)
        return jsonify(data), 200
    except Exception as e:
        current_app.logger.error("Error generating action distribution: %s", str(e))
        return jsonify({"error": "Unable to retrieve action telemetry."}), 500


@dashboard_bp.route("/api/security/rules", methods=["GET"])
def api_rule_frequency():
    """Returns trigger frequency for detection rules (XSS-001 through XSS-006)."""
    try:
        time_range = request.args.get("time_range", "all")
        data = DashboardRepository.get_rule_frequency(time_range=time_range)
        return jsonify(data), 200
    except Exception as e:
        current_app.logger.error("Error generating rule frequency: %s", str(e))
        return jsonify({"error": "Unable to retrieve rule telemetry."}), 500


@dashboard_bp.route("/api/security/endpoints", methods=["GET"])
def api_endpoint_distribution():
    """Returns event counts grouped by application endpoint."""
    try:
        time_range = request.args.get("time_range", "all")
        data = DashboardRepository.get_endpoint_distribution(time_range=time_range)
        return jsonify(data), 200
    except Exception as e:
        current_app.logger.error("Error generating endpoint distribution: %s", str(e))
        return jsonify({"error": "Unable to retrieve endpoint telemetry."}), 500


@dashboard_bp.route("/api/security/timeline", methods=["GET"])
def api_timeline():
    """Returns security event counts over time."""
    try:
        time_range = request.args.get("time_range", "all")
        data = DashboardRepository.get_timeline(time_range=time_range)
        return jsonify(data), 200
    except Exception as e:
        current_app.logger.error("Error generating timeline: %s", str(e))
        return jsonify({"error": "Unable to retrieve timeline telemetry."}), 500


@dashboard_bp.route("/api/security/recent", methods=["GET"])
def api_recent():
    """
    Returns recent security events.
    CRITICAL: Never includes raw attack payloads.
    """
    try:
        limit = request.args.get("limit", 15, type=int)
        time_range = request.args.get("time_range", "all")
        events = DashboardRepository.get_recent_events(limit=limit, time_range=time_range)
        return jsonify({"events": events}), 200
    except Exception as e:
        current_app.logger.error("Error generating recent events: %s", str(e))
        return jsonify({"error": "Unable to retrieve recent events."}), 500
