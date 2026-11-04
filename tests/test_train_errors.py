import asyncio
from types import SimpleNamespace

import numpy as np
import pytest

pytest.importorskip("torch")

from backend import main
from training.train import NotEnoughDataError, train

SHORT = {"n1": (np.arange(10, dtype=float), np.zeros((10, 4)))}


def test_train_raises_catchable_error_when_data_is_short():
    with pytest.raises(NotEnoughDataError):
        train(SHORT, 12, 1, 500, 42, "test")


def test_retrain_loop_survives_short_data(monkeypatch):
    calls = []

    def short_train(*args):
        calls.append(1)
        raise NotEnoughDataError("short")

    monkeypatch.setattr(main, "RETRAIN_CHECK_SECONDS", 0)
    monkeypatch.setattr(main, "load_db", lambda: SHORT)
    monkeypatch.setattr(main, "train", short_train)
    monkeypatch.setattr(main.app.state, "pipeline", SimpleNamespace(ensemble=SimpleNamespace(ready=False)), raising=False)

    async def run():
        task = asyncio.create_task(main._continuous_learning())
        while len(calls) < 2:
            await asyncio.sleep(0)
            assert not task.done()
        task.cancel()

    asyncio.run(run())
