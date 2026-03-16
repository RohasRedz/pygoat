import pytest


def test_ssrf_blog_uses_basename():
    """Ensure SSRF lab uses basename to prevent path traversal when reading blog files."""
    path = "introduction/views.py"
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "os.path.basename(file)" in content
    assert "os.path.join(dirname, safe_filename)" in content
