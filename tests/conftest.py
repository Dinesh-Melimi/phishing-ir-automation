from pathlib import Path

import pytest

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    """Guarantee tests never use live providers or post webhooks."""
    for var in ("PHISHIR_LIVE", "PHISHIR_WEBHOOK_ENABLED", "VT_API_KEY", "ABUSEIPDB_API_KEY", "URLHAUS_API_KEY"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def sample():
    return lambda name: SAMPLES / name
