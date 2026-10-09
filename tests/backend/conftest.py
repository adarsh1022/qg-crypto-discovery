import sys
from pathlib import Path

import pytest

from backend import db

# Phase 1 test helpers (treegen, pemgen, pfxgen, certgen) live next to the agent tests.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agent"))


@pytest.fixture
def conn():
    """A fresh, fully migrated in-memory database."""
    connection = db.open_database(":memory:")
    yield connection
    connection.close()


@pytest.fixture
def api(tmp_path):
    """An application on a temporary database with a controllable clock and the sweeper switched off."""
    from apifx import make_api
    return make_api(tmp_path)
