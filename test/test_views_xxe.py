import types

import pytest


def _make_request(body: bytes, authenticated=True):
    user = types.SimpleNamespace(is_authenticated=authenticated)
    return types.SimpleNamespace(method="POST", body=body, user=user)


def test_xxe_parse_disables_external_general_entities(monkeypatch):
    import introduction.views as views

    called = {}

    class FakeParser:
        def setFeature(self, feature, value):
            called["feature"] = feature
            called["value"] = value

    def fake_make_parser():
        return FakeParser()

    # Minimal pulldom iterator yielding a <text> element
    class FakeNode:
        tagName = "text"

        def toxml(self):
            return "<text>hello</text>"

    class FakeDoc:
        def __iter__(self):
            return iter([(views.START_ELEMENT, FakeNode())])

        def expandNode(self, node):
            return None

    def fake_parse_string(_xml, parser=None):
        return FakeDoc()

    class FakeComments:
        class objects:
            @staticmethod
            def filter(id):
                class _Q:
                    @staticmethod
                    def update(comment):
                        return 1

                return _Q()

    monkeypatch.setattr(views, "make_parser", fake_make_parser)
    monkeypatch.setattr(views, "parseString", fake_parse_string)
    monkeypatch.setattr(views, "comments", FakeComments)
    monkeypatch.setattr(views, "render", lambda request, template, context=None: (template, context))

    req = _make_request(b"<root><text>hello</text></root>")
    template, _ctx = views.xxe_parse(req)

    assert called["feature"] == views.feature_external_ges
    assert called["value"] is False
    assert template == "Lab/XXE/xxe_lab.html"
