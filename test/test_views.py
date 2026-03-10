import pytest

# Assumption: tests run with repo root on PYTHONPATH so "introduction" is importable.
from introduction import views


def test_xxe_parse_disables_external_general_entities(mocker):
    # Arrange
    parser = mocker.Mock()
    make_parser_mock = mocker.patch("introduction.views.make_parser", return_value=parser)

    # Avoid real XML parsing; we only care about the security-relevant parser feature flag.
    mocker.patch("introduction.views.parseString", return_value=[])

    request = mocker.Mock()
    request.user.is_authenticated = True
    request.body = b"<root/>"

    # Act
    views.xxe_parse(request)

    # Assert
    make_parser_mock.assert_called_once()
    parser.setFeature.assert_any_call(views.feature_external_ges, False)
