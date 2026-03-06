from pathlib import Path


def test_lab2_template_no_longer_marks_username_safe():
    template_path = Path("introduction/templates/Lab_2021/A8_software_and_data_integrity_failure/lab2.html")
    content = template_path.read_text(encoding="utf-8")

    assert "{{username | safe}}" not in content
    assert "<h1>Hey {{username}},</h1>" in content
