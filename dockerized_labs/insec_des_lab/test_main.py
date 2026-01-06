# File: dockerized_labs/insec_des_lab/test_main.py
# NOTE: Assumes pytest + Flask's built-in test client usage.
# TODO: Adjust imports if the project structure differs.

import base64
import json

import pytest

from dockerized_labs.insec_des_lab import main as main_module


@pytest.fixture
def app():
    return main_module.app


@pytest.fixture
def client(app):
    return app.test_client()


def test_serialize_uses_json_not_pickle(client):
    """
    Delta test:
    - Before: serialization used pickle.dumps(user) which allowed gadget-based RCE.
    - After: serialization uses JSON (dict) and base64 encoding.
    This test asserts the returned serialized blob is valid base64 JSON and not a pickle.
    """
    response = client.post("/serialize", data={"username": "guest"})
    assert response.status_code == 200

    html = response.data.decode("utf-8")
    # Very simple extraction: assume the serialized value appears in the response.
    # TODO: Adjust selector/parsing if the template changes structure.
    assert "serialized" in html.lower()

    # Extract base64-like token between common delimiters if present
    # Fallback: just search for first base64-looking word.
    token = None
    for part in html.split():
        if all(c.isalnum() or c in "+/=\n\r" for c in part) and len(part) >= 16:
            token = part.strip("<>\"'")  # naive cleanup
            break

    assert token is not None

    # Confirm that it is base64-coded JSON
    decoded = base64.b64decode(token)
    data = json.loads(decoded.decode("utf-8"))
    assert isinstance(data, dict)
    assert data.get("username") == "guest"
    # Ensure no obvious pickle protocol headers
    assert not decoded.startswith(b"\x80")  # typical pickle protocol marker


def test_deserialize_rejects_admin_escalation_payload(client):
    """
    Delta test:
    - Before: user-controlled pickle.loads allowed creating a User with is_admin=True.
    - After: JSON decoding plus forced is_admin=False prevents client-side admin escalation.
    Here we construct a JSON payload that claims is_admin=True and assert that the
    response still treats the user as non-admin.
    """
    payload = {"username": "attacker", "is_admin": True}
    encoded = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8")

    response = client.post("/deserialize", data={"serialized_data": encoded})
    assert response.status_code == 200
    body = response.data.decode("utf-8")

    # The message for non-admin path should be present, and admin secret content absent.
    assert "only admins can see the secret content" in body.lower()
    assert "ADMIN_KEY_123" not in body
