# Assumption: project uses pytest and imports modules by package name "introduction".
# These tests isolate the delta behavior by mocking XML parsing and verifying the parser feature flag.

import introduction.views as views


def test_xxe_parse_disables_external_general_entities(mocker):
    # Arrange
    parser = mocker.Mock()
    make_parser = mocker.patch("introduction.views.make_parser", return_value=parser)

    # Prevent real XML parsing; we only care that parseString is called with the parser.
    mocker.patch("introduction.views.parseString", return_value=[])

    request = mocker.Mock()
    request.body = b"<root/>"

    # Act
    views.xxe_parse(request)

    # Assert
    make_parser.assert_called_once()
    parser.setFeature.assert_called_once_with(views.feature_external_ges, False)
