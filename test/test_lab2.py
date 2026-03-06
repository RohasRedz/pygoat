import pytest


def test_lab2_template_no_longer_marks_username_safe():
    # Regression test for XSS fix: username should not be rendered with the `safe` filter.
    template_path = "introduction/templates/Lab_2021/A8_software_and_data_integrity_failure/lab2.html"
    with open(template_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "username | safe" not in content
    assert "{{username}}" in content
