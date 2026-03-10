import introduction.views as views


def test_xxe_parse_disables_external_general_entities(mocker):
    # Arrange
    parser = mocker.Mock()
    make_parser_mock = mocker.patch.object(views, "make_parser", return_value=parser)

    # Avoid real XML parsing; we only assert the security-relevant parser configuration.
    mocker.patch.object(views, "parseString", return_value=[])
    request = mocker.Mock()
    request.body = b"<root/>"

    # Act
    views.xxe_parse(request)

    # Assert: regression test for XXE fix (external general entities must be disabled)
    make_parser_mock.assert_called_once()
    parser.setFeature.assert_any_call(views.feature_external_ges, False)
