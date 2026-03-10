import os
from pathlib import Path

import pytest


def _is_allowed_path(dirname: str, user_supplied: str) -> bool:
    """
    Mirrors the patched logic in introduction/views.py:
      filename = os.path.join(dirname, file)
      abs_path = os.path.abspath(filename)
      if not abs_path.startswith(os.path.dirname(__file__)): raise
    """
    filename = os.path.join(dirname, user_supplied)
    abs_path = os.path.abspath(filename)
    return abs_path.startswith(dirname)


def test_ssrf_lab_blocks_directory_traversal_outside_base_dir(tmp_path):
    # Arrange
    base_dir = tmp_path / "base"
    base_dir.mkdir()
    dirname = str(base_dir)

    # Act / Assert: traversal should be rejected after fix
    assert _is_allowed_path(dirname, "../outside.txt") is False
    assert _is_allowed_path(dirname, "../../etc/passwd") is False


def test_ssrf_lab_allows_file_within_base_dir(tmp_path):
    # Arrange
    base_dir = tmp_path / "base"
    base_dir.mkdir()
    (base_dir / "ok.txt").write_text("ok", encoding="utf-8")
    dirname = str(base_dir)

    # Act / Assert: normal relative file should be allowed
    assert _is_allowed_path(dirname, "ok.txt") is True
    assert _is_allowed_path(dirname, "./ok.txt") is True
