import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("WATCHTOWER_HOME", str(tmp_path))
    return tmp_path


@pytest.fixture
def db(home):
    from watchtower.storage.db import Database
    d = Database()
    yield d
    d.close()
