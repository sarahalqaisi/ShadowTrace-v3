from __future__ import annotations

import secrets

from flask import Flask, abort, render_template, request, session

from dashboard.config import Config
from dashboard.db import init_app as init_database


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)
    if not app.config.get("SECRET_KEY"):
        raise RuntimeError(
            "SHADOWTRACE_SECRET_KEY is missing. Copy .env.example to .env "
            "and set a strong random value."
        )

    init_database(app)

    from dashboard.routes import main
    app.register_blueprint(main)

    @app.before_request
    def csrf_protect():
        if not app.config.get("CSRF_ENABLED", True) or request.method in {"GET", "HEAD", "OPTIONS"}:
            return None
        expected = session.get("csrf_token")
        supplied = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
        if not expected or not supplied or not secrets.compare_digest(expected, supplied):
            abort(400, description="Invalid or missing CSRF token.")
        return None

    @app.context_processor
    def inject_csrf():
        token = session.get("csrf_token")
        if not token:
            token = secrets.token_urlsafe(32)
            session["csrf_token"] = token
        return {"csrf_token": token}

    @app.after_request
    def security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net https://unpkg.com; "
            "style-src 'self' 'unsafe-inline' https://unpkg.com; img-src 'self' data: https://*.tile.openstreetmap.org https://unpkg.com; "
            "connect-src 'self'; font-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
        )
        return response

    @app.errorhandler(400)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(500)
    def handle_error(error):
        code = getattr(error, "code", 500)
        message = getattr(error, "description", "ShadowTrace encountered an unexpected error.")
        return render_template("error.html", error_code=code, error_message=message), code

    return app
