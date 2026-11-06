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


def _run_ticks(monkeypatch, ready, error, ticks):
    calls = []
    clock = [0.0]

    def fake_train(*args):
        calls.append(clock[0])
        raise error

    real_sleep = asyncio.sleep

    async def fake_sleep(seconds):
        if clock[0] >= ticks * 3600:
            raise asyncio.CancelledError
        clock[0] += 3600
        await real_sleep(0)

    monkeypatch.setattr(main, "_now", lambda: clock[0])
    monkeypatch.setattr(main.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(main, "load_db", lambda: SHORT)
    monkeypatch.setattr(main, "train", fake_train)
    monkeypatch.setattr(main.app.state, "pipeline", SimpleNamespace(ensemble=SimpleNamespace(ready=ready)), raising=False)
    try:
        asyncio.run(main._continuous_learning())
    except asyncio.CancelledError:
        pass
    return calls


def test_ready_model_is_not_retrained_before_24h(monkeypatch):
    assert _run_ticks(monkeypatch, True, NotEnoughDataError("x"), 24) == []


def test_ready_model_retrains_after_24h(monkeypatch):
    assert len(_run_ticks(monkeypatch, True, NotEnoughDataError("x"), 26)) == 1


def test_failed_retrain_with_ready_model_waits_full_interval(monkeypatch):
    calls = _run_ticks(monkeypatch, True, RuntimeError("boom"), 50)
    assert calls == [25 * 3600.0, 49 * 3600.0]


def test_no_model_retries_hourly(monkeypatch):
    assert len(_run_ticks(monkeypatch, False, RuntimeError("boom"), 5)) == 5
