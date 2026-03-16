import pytest


def test_ssrf_lab2_url_is_hardcoded_safe():
    """Ensure SSRF lab2 no longer uses user-supplied URL."""
    path = "introduction/views.py"
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "url = request.POST[\"url\"]" not in content
    assert "url = 'https://safe.example.com/resource'" in content
