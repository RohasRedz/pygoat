from flask import Flask, render_template, request, make_response
import base64
import json
from dataclasses import dataclass

app = Flask(__name__)


@dataclass
class User:
    username: str
    is_admin: bool = False


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/serialize", methods=["POST"])
def serialize_data():
    username = request.form.get("username", "guest")
    user = User(username=username, is_admin=False)

    # SECURITY: Use JSON instead of pickle for serialization of user-controlled data.
    payload = {"username": user.username, "is_admin": user.is_admin}
    serialized = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8")

    return render_template("result.html", serialized=serialized)


@app.route("/deserialize", methods=["POST"])
def deserialize_data():
    try:
        serialized_data = request.form.get("serialized_data", "")
        decoded_data = base64.b64decode(serialized_data)

        # SECURITY: Safe deserialization using JSON with explicit validation
        data = json.loads(decoded_data.decode("utf-8"))

        if not isinstance(data, dict):
            message = "Invalid user data"
        else:
            username = data.get("username")
            is_admin = bool(data.get("is_admin", False))

            # Enforce server-side privilege control regardless of client-supplied flag
            user = User(username=username or "guest", is_admin=False)

            if user.is_admin:
                # This branch will not be reachable with client-controlled data
                message = (
                    f"Welcome Admin {user.username}! "
                    "Here's the secret admin content: ADMIN_KEY_123"
                )
            else:
                message = (
                    f"Welcome {user.username}. "
                    "Only admins can see the secret content."
                )

        return render_template("result.html", message=message)
    except Exception as e:
        # Avoid leaking detailed errors to the user in real apps; kept simple for lab.
        return render_template("result.html", message="Error processing data.")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
