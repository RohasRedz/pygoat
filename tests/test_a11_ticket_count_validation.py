import pytest


def test_ticket_count_validation_present():
    """Ensure A11 ticket count is validated and rejects invalid input."""
    path = "introduction/views.py"
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "raw_count = request.POST.get(\"count\")" in content
    assert "except (ValueError, TypeError)" in content
    assert "count < 0" in content
    assert "(count + len(tkts)) > 5" in content
