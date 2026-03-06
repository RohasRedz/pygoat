import types

import pytest


def test_xxe_parse_disables_external_general_entities(mocker):
    # Regression test for XXE fix: feature_external_ges must be set to False.
    from introduction import views

    parser = mocker.Mock()
    make_parser_spy = mocker.patch("introduction.views.make_parser", return_value=parser)

    # parseString is called with parser=parser; return empty iterator to avoid loop.
    mocker.patch("introduction.views.parseString", return_value=[])

    user = types.SimpleNamespace(is_authenticated=True)
    request = types.SimpleNamespace(method="POST", body=b"<root/>", user=user)

    views.xxe_parse(request)

    make_parser_spy.assert_called_once()
    parser.setFeature.assert_called_once_with(views.feature_external_ges, False)
