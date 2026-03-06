from xml.sax.handler import feature_external_ges

import pytest


# Assumption: tests run with repository root on PYTHONPATH so `introduction` is importable.
from introduction import views


def test_xxe_parse_disables_external_general_entities(monkeypatch):
    calls = {}

    class DummyParser:
        def setFeature(self, feature, value):
            calls["feature"] = feature
            calls["value"] = value

    def fake_make_parser():
        return DummyParser()

    # parseString is used later; stub it to avoid real XML parsing and DB access.
    def fake_parse_string(_xml, parser=None):
        # Ensure our parser instance is passed through
        assert isinstance(parser, DummyParser)
        return []

    # Stub comments ORM chain used at end of xxe_parse
    class DummyFilter:
        def update(self, **kwargs):
            calls["updated_comment"] = kwargs.get("comment")
            return 1

    class DummyComments:
        class objects:
            @staticmethod
            def filter(id):
                return DummyFilter()

    monkeypatch.setattr(views, "make_parser", fake_make_parser)
    monkeypatch.setattr(views, "parseString", fake_parse_string)
    monkeypatch.setattr(views, "comments", DummyComments)
    monkeypatch.setattr(views, "render", lambda request, template, context=None: {"template": template, "context": context})

    class Req:
        user = type("U", (), {"is_authenticated": True})()
        body = b"<root><text>hello</text></root>"

    # Act
    resp = views.xxe_parse(Req())

    # Assert: security fix should disable external entities
    assert calls["feature"] == feature_external_ges
    assert calls["value"] is False
    assert resp["template"] == "Lab/XXE/xxe_lab.html"
