import pytest


def test_lab2_template_no_longer_marks_username_safe():
    # Arrange
    # Template path is not a Python module; validate the security fix directly on template content.
    from pathlib import Path

    template_path = Path("introduction/templates/Lab_2021/A8_software_and_data_integrity_failure/lab2.html")
    content = template_path.read_text(encoding="utf-8")

    # Assert
    assert "{{username | safe}}" not in content
    assert "<h1>Hey {{username}},</h1>" in content
