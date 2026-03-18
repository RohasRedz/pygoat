import pytest


def test_xxe_parse_disables_external_general_entities(mocker):
    """Regression: xxe_parse must disable external general entities to prevent XXE."""
    from introduction import views

    # Arrange
    parser = mocker.Mock()
    make_parser_mock = mocker.patch.object(views, "make_parser", return_value=parser)

    # Stub parseString so we don't parse real XML; return empty iterator.
    mocker.patch.object(views, "parseString", return_value=[])

    request = mocker.Mock()
    request.body = b"<root><text>hello</text></root>"

    # Act + Assert
    # The function will raise because `text` is never set when parseString yields nothing.
    # We intentionally accept this to focus only on the security-relevant behavior change.
    with pytest.raises(UnboundLocalError):
        views.xxe_parse(request)

    make_parser_mock.assert_called_once()
    parser.setFeature.assert_any_call(views.feature_external_ges, False)
