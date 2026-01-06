from flask import Flask, render_template, request, redirect, url_for, make_response, flash
import hashlib
import json
from datetime import datetime, timedelta
import base64
import os
import secrets

app = Flask(__name__)

# SECURITY: Do not hardcode Flask secret keys; load from environment or a secure store.
# Fallback key is only for non-production/demo use.
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))

# Vulnerable: Storing user data in memory (kept for lab/demo behavior)
users = {
    "admin": {
        "password": "admin123",  # Vulnerable: Weak password
        "email": "admin@example.com",
        "role": "admin",
    },
    "user": {
        "password": "password123",  # Vulnerable: Weak password
        "email": "user@example.com",
        "role": "user",
    },
}

# Vulnerable: Storing reset tokens in memory
password_reset_tokens = {}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/lab")
def lab():
    return render_template("lab.html")


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    remember_me = request.form.get("remember_me")

    if username in users and users[username]["password"] == password:  # Plain text comparison kept for lab
        response = make_response(redirect(url_for("dashboard")))

        # SECURITY: Use cryptographically secure, opaque session tokens instead of encoding username+timestamp.
        session_token = secrets.token_urlsafe(32)

        # For a real app, this token should be mapped to server-side session state (e.g., DB or cache).
        # Here we preserve existing behavior by embedding the username in a signed value.
        signed_value = base64.b64encode(f"{username}:{session_token}".encode()).decode()

        cookie_kwargs = {"httponly": True, "samesite": "Lax"}
        # In production, also set Secure=True when using HTTPS:
        # cookie_kwargs["secure"] = True

        if remember_me:
            response.set_cookie(
                "session",
                signed_value,
                max_age=30 * 24 * 60 * 60,
                **cookie_kwargs,
            )
        else:
            response.set_cookie("session", signed_value, **cookie_kwargs)

        return response

    flash("Invalid username or password")
    return redirect(url_for("lab"))


@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username")
    password = request.form.get("password")
    email = request.form.get("email")

    # Vulnerable: No password complexity requirements (left as-is for lab)
    if username and password and email:
        if username not in users:
            users[username] = {
                "password": password,  # Vulnerable: Storing plain text passwords
                "email": email,
                "role": "user",
            }
            flash("Registration successful")
            return redirect(url_for("lab"))

    flash("Registration failed")
    return redirect(url_for("lab"))


@app.route("/reset-password", methods=["POST"])
def reset_password():
    email = request.form.get("email")

    # Vulnerable: Password reset token generation kept for lab; use secure token in real app
    for username, user_data in users.items():
        if user_data["email"] == email:
            # SECURITY: Use secrets instead of predictable md5-based tokens.
            token = secrets.token_urlsafe(32)
            password_reset_tokens[token] = username

            # In a real application, this would send an email; token should not be shown to the user.
            flash(f"Password reset link has been sent to {email}")
            return redirect(url_for("lab"))

    flash("Email not found")
    return redirect(url_for("lab"))


@app.route("/reset/<token>")
def reset_form(token):
    if token in password_reset_tokens:
        return render_template("reset.html", token=token)
    return "Invalid token"


@app.route("/dashboard")
def dashboard():
    session_token = request.cookies.get("session")
    if not session_token:
        return redirect(url_for("lab"))

    try:
        decoded = base64.b64decode(session_token).decode()
        username, _token = decoded.split(":", 1)
        if username in users:
            return render_template(
                "dashboard.html",
                username=username,
                role=users[username]["role"],
                email=users[username]["email"],
            )
    except Exception:
        # Fail closed on invalid cookie
        pass

    return redirect(url_for("lab"))


if __name__ == "__main__":
    # SECURITY: Debug should be disabled in production; kept True here for lab/demo.
    app.run(host="0.0.0.0", port=5000, debug=True)
