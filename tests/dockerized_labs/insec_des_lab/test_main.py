import json

import pytest
from dockerized_labs.insec_des_lab import main as main_module


@pytest.fixture
def client():
    app = main_module.app
    app.config.update({"TESTING": True})
    with app.test_client() as c:
        yield c


def test_index_rejects_invalid_json(client):
    """
    Secure behavior: invalid JSON input must not be deserialized into objects;
    instead, request should be rejected with an error.
    """
    resp = client.post("/", data="not-json", content_type="application/json")
    assert resp.status_code == 200
    assert b"Invalid JSON data" in resp.data


def test_index_rejects_unexpected_keys(client):
    """
    Secure behavior: JSON containing unexpected keys must be rejected
    by _validate_payload.
    """
    payload = {"username": "alice", "role": "user", "unexpected": "value"}
    resp = client.post("/", data=json.dumps(payload), content_type="application/json")
    assert resp.status_code == 400
    assert b"Invalid payload" in resp.data


def test_index_accepts_valid_payload(client):
    """
    Positive path: a valid payload with allowed keys should be accepted
    and rendered without errors.
    """
    payload = {"username": "alice", "role": "admin", "preferences": {"theme": "dark"}}
    resp = client.post("/", data=json.dumps(payload), content_type="application/json")
    assert resp.status_code == 200
    assert b"alice" in resp.data
    assert b"admin" in resp.data


def test_validate_payload_rejects_non_dict():
    """
    Secure behavior: _validate_payload must enforce dict type and fail on others.
    """
    with pytest.raises(ValueError):
        main_module._validate_payload(["not-a-dict"])
