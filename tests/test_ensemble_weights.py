import pytest

pytest.importorskip("torch")

from backend.config import settings
from backend.main import Weights, build_ensemble


def test_transformer_weight_from_settings():
    assert build_ensemble(settings).weights["transformer"] > 0


def test_weights_model_accepts_transformer():
    assert Weights(iforest=1, lstm=1, vae=1, transformer=1).transformer == 1
