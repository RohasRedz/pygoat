import importlib
import types

import pytest


def _import_views_module():
    # Assumption: Django app module path is "introduction.views" based on file_path.
    return importlib.import_module("introduction.views")


def test_xxe_parse_disables_external_general_entities(mocker):
    """
    Delta test for XXE hardening:
    - Previously: feature_external_ges was enabled (True)
    - Now: feature_external_ges must be disabled (False)
    """
    views = _import_views_module()

    # Arrange
    parser_mock = mocker.Mock()
    make_parser_mock = mocker.patch.object(views, "make_parser", return_value=parser_mock)

    # parseString returns an iterable of (event, node) pairs; keep it empty to avoid deeper logic.
    mocker.patch.object(views, "parseString", return_value=[])

    # request.body is read and decoded
    request = types.SimpleNamespace(body=b"<root/>")

    # Act
    views.xxe_parse(request)

    # Assert
    make_parser_mock.assert_called_once()
    parser_mock.setFeature.assert_any_call(views.feature_external_ges, False)
