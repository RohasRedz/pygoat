import os

import pytest


@pytest.mark.django_db
def test_ssrf_lab_sanitizes_blog_filename_with_basename(client, django_user_model, monkeypatch):
    # Arrange: login
    django_user_model.objects.create_user(username="u1", password="p1")
    assert client.login(username="u1", password="p1")

    import introduction.views as views

    opened_paths = []

    def fake_open(path, mode="r", *args, **kwargs):
        opened_paths.append(path)

        class _F:
            def read(self_inner):
                return "blog content"

        return _F()

    monkeypatch.setattr(views, "open", fake_open)

    # Act: attempt traversal
    resp = client.post("/ssrf_lab", data={"blog": "../../etc/passwd"})

    # Assert
    assert resp.status_code == 200
    assert opened_paths, "Expected the view to attempt opening a file"
    opened = opened_paths[0]
    assert opened.endswith(os.path.sep + "passwd") or opened.endswith("/passwd") or opened.endswith("\\passwd")
    assert ".." not in opened
