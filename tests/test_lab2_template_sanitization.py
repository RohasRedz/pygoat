import pytest


def test_lab2_template_does_not_use_safe_filter():
    """Regression test: ensure user-controlled username is not marked safe in template."""
    template_path = "introduction/templates/Lab_2021/A8_software_and_data_integrity_failure/lab2.html"
    with open(template_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "{{username | safe}}" not in content
    assert "{{ username }}" in content
