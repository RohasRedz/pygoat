import pytest


def test_xxe_external_entities_disabled():
    """Ensure XXE parser disables external general entities."""
    path = "introduction/views.py"
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "parser.setFeature(feature_external_ges, False)" in content
