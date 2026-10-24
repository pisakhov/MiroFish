"""Single-operator experiment boundary; not multi-tenant authorization."""
import hmac
import re

from flask import jsonify, request

_IDENTIFIER = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_PLATFORMS = {"twitter", "reddit", "parallel"}


def validate_inputs(value):
    """Reject path syntax in identifiers, including nested batch requests."""
    if isinstance(value, dict):
        for key, item in value.items():
            if key in {"simulation_id", "project_id", "report_id"}:
                if not isinstance(item, str) or not _IDENTIFIER.fullmatch(item):
                    return False
            if key == "platform" and item is not None:
                if not isinstance(item, str) or item not in _PLATFORMS:
                    return False
            if not validate_inputs(item):
                return False
    elif isinstance(value, list):
        return all(validate_inputs(item) for item in value)
    return True


def install_security(app):
    username = app.config.get("EXPERIMENT_USERNAME", "")
    password = app.config.get("EXPERIMENT_PASSWORD", "")
    if not username or len(password) < 32:
        raise RuntimeError("Set EXPERIMENT_USERNAME and EXPERIMENT_PASSWORD (at least 32 characters)")
    if app.config.get("DEBUG"):
        raise RuntimeError("Debug mode is forbidden in the hardened fork")

    @app.before_request
    def protect_request():
        if request.path == "/health" and request.method in {"GET", "HEAD"}:
            return None
        auth = request.authorization
        if not (auth and auth.type == "basic"
                and hmac.compare_digest((auth.username or "").encode(), username.encode())
                and hmac.compare_digest((auth.password or "").encode(), password.encode())):
            response = jsonify(success=False, error="Authentication required")
            response.status_code = 401
            response.headers["WWW-Authenticate"] = 'Basic realm="MiroFish private experiment", charset="UTF-8"'
            return response
        # Browser Basic credentials are ambient. Require a non-simple header and
        # reject cross-origin requests; no CORS permission is granted by this app.
        if request.headers.get("Sec-Fetch-Site") == "cross-site":
            return jsonify(success=False, error="Cross-site requests are forbidden"), 403
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            if request.headers.get("X-MiroFish-Request") != "1":
                return jsonify(success=False, error="Missing request protection header"), 403
        sources = [request.view_args or {}, request.get_json(silent=True)]
        sources.extend({key: value} for key, value in request.args.items(multi=True))
        sources.extend({key: value} for key, value in request.form.items(multi=True))
        if not all(validate_inputs(source) for source in sources):
            return jsonify(success=False, error="Invalid resource identifier or platform"), 400

    @app.after_request
    def protect_response(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        # Upstream handlers frequently expose tracebacks and provider exceptions.
        if response.status_code >= 500 and request.path.startswith("/api/"):
            response.set_data(app.json.dumps({"success": False, "error": "Internal server error"}))
            response.content_type = "application/json"
        return response
