import pytest

# Assumption: "introduction" is importable from tests.
from introduction import views


def test_xxe_parse_disables_external_general_entities(mocker):
    # Arrange
    parser = mocker.Mock()
    make_parser_mock = mocker.patch.object(views, "make_parser", return_value=parser)

    # parseString is imported into module namespace; patch it to avoid real XML parsing.
    parse_string_mock = mocker.patch.object(views, "parseString", return_value=[])
    request = mocker.Mock()
    request.body = b"<root/>"

    # Act
    views.xxe_parse(request)

    # Assert
    make_parser_mock.assert_called_once()
    parser.setFeature.assert_called_once_with(views.feature_external_ges, False)
    parse_string_mock.assert_called_once()
