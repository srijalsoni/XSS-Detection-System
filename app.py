import os
import uuid
from flask import Flask, jsonify, g, request
from config import config_by_name
from logger import setup_logger
from database import close_db, init_database
from security import apply_security_headers


def create_app(config_name=None):
    """
    Application factory for P_211 Defensive Web Application.
    Supports modular configuration (development, testing).
    """
    if config_name is None:
        config_name = os.environ.get("FLASK_ENV", "development")

    app = Flask(__name__)
    config_obj = config_by_name.get(config_name, config_by_name["default"])
    app.config.from_object(config_obj)

    # Initialize centralized logger
    log_level = "DEBUG" if app.config.get("DEBUG") else "INFO"
    app_logger = setup_logger("p211_app", level=log_level)
    app.logger = app_logger
    app.logger.info("Application initialized with config: %s", config_name)

    # Automatically ensure SQLite database schema exists
    init_database(app.config.get("DATABASE_PATH"))

    # Teardown database connections after request completion
    app.teardown_appcontext(close_db)

    # Middleware: Attach unique request_id to each incoming request
    @app.before_request
    def assign_request_id():
        g.request_id = str(uuid.uuid4())

    @app.after_request
    def attach_request_id_and_security_headers(response):
        if hasattr(g, "request_id"):
            response.headers["X-Request-ID"] = g.request_id
        # Phase 5: Attach robust defense-in-depth security headers
        return apply_security_headers(response)

    # Register blueprints
    from routes.main_routes import main_bp
    from routes.feature_routes import feature_bp
    from routes.dashboard_routes import dashboard_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(feature_bp)
    app.register_blueprint(dashboard_bp)

    # Error handling
    register_error_handlers(app)

    return app


def register_error_handlers(app):
    """Register centralized error handlers that prevent stack/path leakage."""

    @app.errorhandler(404)
    def not_found_error(error):
        app.logger.warning("Resource not found: 404")
        return jsonify({
            "error": "Not Found",
            "message": "The requested URL was not found on the server."
        }), 404

    @app.errorhandler(500)
    def internal_server_error(error):
        app.logger.error("Internal server error: %s", str(error))
        return jsonify({
            "error": "Internal Server Error",
            "message": "An internal error occurred. Please contact the administrator."
        }), 500


if __name__ == "__main__":
    app = create_app("development")
    app.run(host="127.0.0.1", port=5000, debug=True)
