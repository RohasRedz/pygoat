from types import SimpleNamespace

# Assumption: Django app module path is "introduction.views" based on file_path "introduction/views.py".
import introduction.views as views


def test_xxe_parse_disables_external_general_entities(mocker):
    # Arrange
    parser = mocker.Mock()
    make_parser_mock = mocker.patch.object(views, "make_parser", return_value=parser)
    parse_string_mock = mocker.patch.object(views, "parseString", return_value=[])
    request = SimpleNamespace(
        user=SimpleNamespace(is_authenticated=True),
        body=b"<root><text>Hello</text></root>",
    )

    # Act
    views.xxe_parse(request)

    # Assert
    make_parser_mock.assert_called_once()
    parser.setFeature.assert_called_once_with(views.feature_external_ges, False)
    parse_string_mock.assert_called_once()
