from types import SimpleNamespace

import pytest

# Assumption: tests run with repo root on PYTHONPATH so "introduction" is importable.
import introduction.views as views


def test_xxe_parse_disables_external_general_entities(monkeypatch):
    # Arrange
    parser_calls = {"features": []}

    class _FakeParser:
        def setFeature(self, feature, value):
            parser_calls["features"].append((feature, value))

    def _fake_make_parser():
        return _FakeParser()

    def _fake_parse_string(_xml, parser):
        # Ensure the parser passed is our fake parser
        assert isinstance(parser, _FakeParser)
        return []  # no events; function will error later, but we only care about setFeature

    monkeypatch.setattr(views, "make_parser", _fake_make_parser)
    monkeypatch.setattr(views, "parseString", _fake_parse_string)

    request = SimpleNamespace(
        user=SimpleNamespace(is_authenticated=True),
        body=b"<root/>",
    )

    # Act / Assert: function may raise due to missing expected XML structure; that's fine for this delta test.
    with pytest.raises(Exception):
        views.xxe_parse(request)

    assert (views.feature_external_ges, False) in parser_calls["features"]
