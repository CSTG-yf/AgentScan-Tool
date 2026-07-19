from pathlib import Path

import pytest


@pytest.fixture
def range_root():
    return Path(__file__).resolve().parents[1]
