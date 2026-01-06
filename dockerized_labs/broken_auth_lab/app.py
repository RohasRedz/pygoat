import os
from flask import Flask, session, redirect, url_for, request, render_template
from werkzeug.middleware.proxy_fix import ProxyFix
from functools import wraps
import secrets

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def _get_secret_key() -> str:
    """
    Retrieve Flask SECRET_KEY from a secure source.

    Priority:
      1. BROKEN_AUTH_SECRET_KEY (lab-specific)
      2. FLASK_SECRET_KEY
      3. Generate a random ephemeral key (non-production fallback)

    In a real deployment, this must come from environment or a secret manager.
    """
    key = os.getenv("BROKEN_AUTH_SECRET_KEY") or os.getenv("FLASK_SECRET_KEY")
    if key:
        return key

    # Ephemeral fallback for local/demo only  avoid hardcoding.
    # NOTE: This must NOT be used in real production deployments.
    return secrets.token_urlsafe(32)


def create_app() -> Flask:
    app = Flask(__name__)
    # Do NOT hardcode the secret key in source control.
    app.secret_key = _get_secret_key()

    # Typical hardening for proxied deployments
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

    # -----------------------------------------------------------------------
    # Simple auth helpers
    # -----------------------------------------------------------------------

    def login_required(view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            if not session.get("user_id"):
                return redirect(url_for("login", next=request.path))
            return view_func(*args, **kwargs)

        return wrapped

    @app.route("/")
    def index():
        if session.get("user_id"):
            return render_template("index.html", user_id=session["user_id"])
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            return render_template("login.html")

        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # NOTE: In labs this may be intentionally weak, but we still avoid logging secrets
        if not username or not password:
            # Do not reveal which field is wrong
            return render_template("login.html", error="Invalid credentials.")

        # Demo-only static check; in a real app, use a user DB + password hashing
        if username == "admin" and password == "admin123":
            session["user_id"] = username
            next_url = request.args.get("next") or url_for("index")
            # Ensure internal redirect only
            if not next_url.startswith("/"):
                next_url = url_for("index")
            return redirect(next_url)

        return render_template("login.html", error="Invalid credentials.")

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/profile")
    @login_required
    def profile():
        return render_template("profile.html", user_id=session["user_id"])

    return app


if __name__ == "__main__":
    # For local testing only; in production use a WSGI server (gunicorn, uWSGI, etc.)
    application = create_app()
    application.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=False)
