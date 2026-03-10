import pytest

# Assumption: tests run with repo root on PYTHONPATH so `introduction` is importable.
import introduction.views as views


def test_xxe_parse_disables_external_general_entities(mocker):
    # Arrange
    parser = mocker.Mock()
    make_parser_spy = mocker.patch.object(views, "make_parser", return_value=parser)

    # Prevent real XML parsing; we only care that the parser feature is set securely.
    mocker.patch.object(views, "parseString", return_value=[])

    request = mocker.Mock()
    request.body = b"<root/>"

    # Act
    views.xxe_parse(request)

    # Assert
    make_parser_spy.assert_called_once()
    parser.setFeature.assert_any_call(views.feature_external_ges, False)
