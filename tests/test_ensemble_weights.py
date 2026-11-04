import pytest

pytest.importorskip("torch")

from backend.config import settings
from backend.main import build_ensemble


def test_transformer_weight_from_settings():
    assert build_ensemble(settings).weights["transformer"] > 0
