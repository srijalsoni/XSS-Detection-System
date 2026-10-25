from flask import Blueprint, jsonify, render_template

main_bp = Blueprint("main", __name__)


@main_bp.route("/", methods=["GET"])
def home():
    """Render the application home page."""
    return render_template("index.html")


@main_bp.route("/health", methods=["GET"])
def health():
    """
    Health check endpoint returning system status.
    Safe metadata only.
    """
    return jsonify({
        "status": "ok",
        "phase": "Phase 9 - Final Hardening, Packaging & Comprehensive Defense Documentation",
        "service": "Cross-Site Scripting (XSS) Attack Detection and Security Monitoring System"
    }), 200
