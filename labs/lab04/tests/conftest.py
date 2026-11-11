import json
from pathlib import Path
from typing import Any

import pytest


# Забороняє мережу та видаляє успадкований ключ перед тестом.
@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.delattr("requests.sessions.Session.request")


# Завантажує незалежну синтетичну відповідь для кожного тесту.
@pytest.fixture
def payload() -> dict[str, Any]:
    sample = Path(__file__).resolve().parents[1] / "data" / "nvd_sample.json"
    return json.loads(sample.read_text(encoding="utf-8"))


# Надає запис CVE із поточної тестової відповіді.
@pytest.fixture
def cve(payload: dict[str, Any]) -> dict[str, Any]:
    return payload["vulnerabilities"][0]["cve"]


# Надає вибрану оцінку для перевірки граничних випадків.
@pytest.fixture
def metric(cve: dict[str, Any]) -> dict[str, Any]:
    return cve["metrics"]["cvssMetricV31"][0]
