import json
from flask import Flask, request, render_template, abort
from typing import Any, Dict

app = Flask(__name__)


def _validate_payload(payload: Any) -> Dict[str, Any]:
    """
    Strictly validate the deserialized payload.

    Requirements (example  tune for your use case):
      - Must be a dict
      - Only specific keys allowed
      - Value types constrained
    """
    if not isinstance(payload, dict):
        raise ValueError("Payload must be an object")

    allowed_keys = {"username", "role", "preferences"}
    if not set(payload.keys()).issubset(allowed_keys):
        raise ValueError("Unexpected keys in payload")

    username = payload.get("username")
    if username is not None and not isinstance(username, str):
        raise ValueError("Invalid username")

    role = payload.get("role", "user")
    if role not in {"user", "admin"}:
        raise ValueError("Invalid role")

    prefs = payload.get("preferences") or {}
    if not isinstance(prefs, dict):
        raise ValueError("Invalid preferences")

    return {"username": username, "role": role, "preferences": prefs}


@app.route("/", methods=["GET", "POST"])
def index():
    """
    Demonstrates secure handling of user-supplied structured data.

    Original issue: using pickle.loads or similar on user input at L36.
    Fix: use JSON with strict validation instead of unsafe deserialization.
    """
    if request.method == "GET":
        return render_template("index.html")

    raw = request.form.get("data") or request.data.decode("utf-8", errors="ignore")
    if not raw:
        return render_template("index.html", error="No data provided.")

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return render_template("index.html", error="Invalid JSON data.")

    try:
        payload = _validate_payload(parsed)
    except ValueError as exc:
        return render_template("index.html", error="Invalid payload."), 400

    username = payload.get("username") or "guest"
    role = payload.get("role", "user")

    return render_template("profile.html", username=username, role=role, preferences=payload["preferences"])


@app.errorhandler(400)
def bad_request(_e):
    return "Bad request.", 400


@app.errorhandler(500)
def server_error(_e):
    return "Internal server error.", 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)
