import math
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from labs.lab04.config import ALLOWED_VALUES, RULES


# Зберігає перевірену оцінку та незмінні значення полів.
@dataclass(frozen=True)
class CVSSMetric:
    """Перевірені метадані та поля правила без змінюваних вкладень."""

    score: float
    version: str | None
    source: str | None
    vector: str | None
    values: Mapping[str, str | None]


# Зберігає опис, статус і перевірену незмінну оцінку.
@dataclass(frozen=True)
class VulnerabilityRecord:
    """Внутрішній запис: опис, статус, перевірена метрика або None."""

    description: str | None
    vuln_status: str | None
    metric: CVSSMetric | None = None


# Повідомляє про порушення контракту даних через ValueError.
def _require(condition: bool, message: str) -> None:
    """Вимагати виконання умови перевірки зовнішніх даних."""
    if not condition:
        raise ValueError(message)


# Відрізняє відсутній рядок від некоректного наявного значення.
def _optional_text(data: dict[str, Any], field: str) -> str | None:
    """Перевірити необов'язковий непорожній текст без підміни помилок."""
    if field not in data:
        return None
    value = data[field]
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Поле {field} має бути непорожнім рядком.")
    return value


# Перевіряє всі описи й вибирає перший англійський.
def _extract_description(cve: dict[str, Any]) -> str | None:
    """Повернути перший непорожній англійський опис."""
    descriptions = cve.get("descriptions", [])
    _require(isinstance(descriptions, list), "Поле descriptions має бути списком.")
    result = None
    for item in descriptions:
        _require(
            isinstance(item, dict)
            and isinstance(item.get("lang"), str)
            and isinstance(item.get("value"), str),
            "Кожен опис має містити рядки lang і value.",
        )
        if result is None and item["lang"] == "en" and item["value"].strip():
            result = item["value"]
    return result


# Перевіряє оцінку та метадані лише вибраного джерела.
def _validate_metric(metric: dict[str, Any]) -> CVSSMetric:
    """Перевірити метрику та зберегти лише потрібні незмінні дані."""
    data = metric.get("cvssData")
    _require(isinstance(data, dict), "Поле cvssData має бути словником.")
    score = data.get("baseScore")
    if (
        isinstance(score, bool)
        or not isinstance(score, (int, float))
        or not 0 <= score <= 10
        or not math.isfinite(score)
    ):
        raise ValueError("Поле baseScore має бути скінченним числом від 0 до 10.")
    version = _optional_text(data, "version")
    if version is not None and version != "3.1":
        raise ValueError("Вибрана оцінка повинна мати версію 3.1.")
    return CVSSMetric(
        score=score,
        version=version,
        vector=_optional_text(data, "vectorString"),
        source=_optional_text(metric, "source"),
        values=MappingProxyType(
            {
                field: data[field] if isinstance(data[field], str) else None
                for field in ALLOWED_VALUES
                if field in data
            }
        ),
    )


# Вибирає першу Primary та перевіряє тільки її дані.
def _extract_metric(cve: dict[str, Any]) -> CVSSMetric | None:
    """Повернути вибрану оцінку 3.1 або None за відсутності."""
    if "metrics" not in cve:
        return None
    metrics = cve["metrics"]
    _require(isinstance(metrics, dict), "Поле metrics має бути словником.")
    if "cvssMetricV31" not in metrics:
        return None
    candidates = metrics["cvssMetricV31"]
    _require(isinstance(candidates, list), "Поле cvssMetricV31 має бути списком.")
    if not candidates:
        return None
    if any(not isinstance(candidate, dict) for candidate in candidates):
        raise ValueError("Кожна оцінка cvssMetricV31 має бути словником.")

    selected = next(
        (candidate for candidate in candidates if candidate.get("type") == "Primary"),
        candidates[0],
    )
    return _validate_metric(selected)


# Перевіряє обгортку NVD та формує незалежний внутрішній запис.
def extract_record(payload: Any, cve_id: str) -> VulnerabilityRecord | None:
    """Повернути опис, статус і незмінну метрику; порожній пошук дає None."""
    _require(isinstance(payload, dict), "Відповідь NVD має бути словником.")
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list) or len(vulnerabilities) > 1:
        raise ValueError("Поле vulnerabilities має містити нуль або один запис.")
    if not vulnerabilities:
        return None

    item = vulnerabilities[0]
    _require(
        isinstance(item, dict) and isinstance(item.get("cve"), dict),
        "Запис має містити словник cve.",
    )
    cve = item["cve"]
    if cve.get("id") != cve_id:
        raise ValueError("Ідентифікатор відповіді не збігається із запитаним CVE.")

    vuln_status = _optional_text(cve, "vulnStatus")
    description = _extract_description(cve)
    metric = _extract_metric(cve) if vuln_status not in (None, "Rejected") else None
    return VulnerabilityRecord(description, vuln_status, metric)


# Формує звіт і застосовує правило до тієї самої оцінки.
def build_report(
    record: VulnerabilityRecord | None, cve_id: str, variant: int
) -> dict[str, Any]:
    """Застосувати правило варіанта без зміни переданих даних."""
    if type(variant) is not int or variant not in RULES:
        raise ValueError("Номер варіанта має бути цілим числом від 1 до 15.")
    threshold, field, expected = RULES[variant]
    report = {
        "cve_id": cve_id,
        "variant": variant,
        "description": None,
        "vuln_status": None,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "rule": {"threshold": threshold, "field": field, "expected": expected},
        "observed": None,
        "decision": "not_found",
    }
    if record is None:
        return report
    _require(
        isinstance(record, VulnerabilityRecord),
        "Очікується внутрішній запис VulnerabilityRecord або None.",
    )
    report.update(description=record.description, vuln_status=record.vuln_status)
    if record.vuln_status == "Rejected":
        report["decision"] = "rejected"
        return report
    report["decision"] = "insufficient_data"
    if record.vuln_status is None or record.metric is None:
        return report

    metric = record.metric
    report.update(
        cvss_version=metric.version,
        score=metric.score,
        score_source=metric.source,
        vector=metric.vector,
    )
    if field not in metric.values:
        return report
    observed = metric.values[field]
    if not isinstance(observed, str) or observed not in ALLOWED_VALUES[field]:
        raise ValueError(f"Поле {field} містить недопустиме значення.")
    report["observed"] = observed
    report["decision"] = (
        "review" if metric.score >= threshold and observed == expected else "other"
    )
    return report
