from copy import deepcopy
from dataclasses import FrozenInstanceError
from typing import Any

import pytest

from labs.lab04.analysis import build_report, extract_record

CVE_ID = "CVE-2099-10001"


# Звіряє весь демонстраційний звіт із явним очікуваним результатом.
def test_sample_report(payload: dict[str, Any]) -> None:
    assert build_report(extract_record(payload, CVE_ID), CVE_ID, 9) == {
        "cve_id": CVE_ID,
        "variant": 9,
        "description": "Synthetic vulnerability for offline API testing.",
        "vuln_status": "Analyzed",
        "cvss_version": "3.1",
        "score": 9.8,
        "score_source": "nvd@nist.gov",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "rule": {"threshold": 5.0, "field": "attackVector", "expected": "LOCAL"},
        "observed": "NETWORK",
        "decision": "other",
    }


# Перевіряє поріг дев'ятого варіанта та невідповідний вектор.
@pytest.mark.parametrize(
    "score, vector, expected",
    [
        (4.9, "LOCAL", "other"),
        (5.0, "LOCAL", "review"),
        (5.1, "LOCAL", "review"),
        (9.8, "NETWORK", "other"),
        (10, "PHYSICAL", "other"),
        (0, "LOCAL", "other"),
    ],
)
def test_variant_nine_boundaries(
    payload: dict[str, Any],
    metric: dict[str, Any],
    score: float,
    vector: str,
    expected: str,
) -> None:
    metric["cvssData"].update(baseScore=score, attackVector=vector)
    report = build_report(extract_record(payload, CVE_ID), CVE_ID, 9)
    assert report["decision"] == expected
    assert report["score"] == score
    assert report["observed"] == vector


# Перевіряє відсутній запис і порожні поля даних.
def test_not_found() -> None:
    record = extract_record({"vulnerabilities": []}, CVE_ID)
    assert record is None
    report = build_report(record, CVE_ID, 9)
    assert report["decision"] == "not_found"
    assert report["rule"] == {
        "threshold": 5.0,
        "field": "attackVector",
        "expected": "LOCAL",
    }
    for field in (
        "description",
        "vuln_status",
        "cvss_version",
        "score",
        "score_source",
        "vector",
        "observed",
    ):
        assert report[field] is None


# Відхиляє неправильну структуру зовнішньої відповіді.
@pytest.mark.parametrize(
    "invalid",
    [
        None,
        [],
        "text",
        {},
        {"vulnerabilities": None},
        {"vulnerabilities": {}},
        {"vulnerabilities": [None]},
        {"vulnerabilities": [{}]},
        {"vulnerabilities": [{"cve": None}]},
        {"vulnerabilities": [{"cve": {"id": "CVE-2099-99999"}}]},
        {"vulnerabilities": [{}, {}]},
    ],
)
def test_invalid_wrapper(invalid: Any) -> None:
    with pytest.raises(ValueError):
        extract_record(invalid, CVE_ID)


# Не аналізує оцінки відхиленого запису або відсутнього статусу.
@pytest.mark.parametrize(
    "status, expected", [("Rejected", "rejected"), (None, "insufficient_data")]
)
def test_status_precedes_metrics(
    payload: dict[str, Any], cve: dict[str, Any], status: str | None, expected: str
) -> None:
    if status is None:
        del cve["vulnStatus"]
    else:
        cve["vulnStatus"] = status
    cve["metrics"] = None
    report = build_report(extract_record(payload, CVE_ID), CVE_ID, 9)
    assert report["decision"] == expected
    assert report["vuln_status"] == status
    assert report["description"] == "Synthetic vulnerability for offline API testing."
    for field in ("cvss_version", "score", "score_source", "vector", "observed"):
        assert report[field] is None


# Відрізняє відсутній статус від некоректного наявного.
@pytest.mark.parametrize("invalid", [None, "", "  ", 123, [], False])
def test_invalid_status(
    payload: dict[str, Any], cve: dict[str, Any], invalid: Any
) -> None:
    cve["vulnStatus"] = invalid
    with pytest.raises(ValueError):
        extract_record(payload, CVE_ID)


# Вибирає перший непорожній англійський опис без запасної мови.
def test_description_selection(payload: dict[str, Any], cve: dict[str, Any]) -> None:
    cve["descriptions"] = [
        {"lang": "uk", "value": "Український опис"},
        {"lang": "en", "value": "  "},
        {"lang": "en", "value": "First English description"},
        {"lang": "en", "value": "Second English description"},
    ]
    assert extract_record(payload, CVE_ID).description == "First English description"
    cve["descriptions"] = [{"lang": "uk", "value": "Опис"}]
    assert extract_record(payload, CVE_ID).description is None
    del cve["descriptions"]
    assert extract_record(payload, CVE_ID).description is None


# Перевіряє тип кожного опису, навіть після знайденого англійського.
@pytest.mark.parametrize(
    "invalid",
    [
        None,
        {},
        "text",
        [None],
        [{}],
        [{"lang": "en", "value": None}],
        [{"lang": 1, "value": "text"}],
        [{"lang": "en", "value": "Valid English description"}, None],
    ],
)
def test_invalid_descriptions(
    payload: dict[str, Any], cve: dict[str, Any], invalid: Any
) -> None:
    cve["descriptions"] = invalid
    with pytest.raises(ValueError):
        extract_record(payload, CVE_ID)


# Відсутні оцінки версії 3.1 означають недостатність даних.
@pytest.mark.parametrize(
    "metrics", [{}, {"cvssMetricV31": []}, {"cvssMetricV30": [None]}]
)
def test_missing_metrics(
    payload: dict[str, Any], cve: dict[str, Any], metrics: dict[str, Any]
) -> None:
    cve["metrics"] = metrics
    assert (
        build_report(extract_record(payload, CVE_ID), CVE_ID, 9)["decision"]
        == "insufficient_data"
    )
    del cve["metrics"]
    assert build_report(extract_record(payload, CVE_ID), CVE_ID, 9)["score"] is None


# Відхиляє неправильні контейнери та елементи списку оцінок.
@pytest.mark.parametrize(
    "invalid",
    [
        None,
        [],
        {"cvssMetricV31": None},
        {"cvssMetricV31": {}},
        {"cvssMetricV31": [None]},
        {"cvssMetricV31": [{}]},
    ],
)
def test_invalid_metrics(
    payload: dict[str, Any], cve: dict[str, Any], invalid: Any
) -> None:
    cve["metrics"] = invalid
    with pytest.raises(ValueError):
        extract_record(payload, CVE_ID)


# Відхиляє некоректну оцінку, включно з bool і нескінченністю.
@pytest.mark.parametrize(
    "invalid",
    [
        None,
        True,
        False,
        "9.8",
        -0.1,
        10.1,
        float("nan"),
        float("inf"),
        float("-inf"),
        [],
        {},
        10**400,
    ],
)
def test_invalid_score(
    payload: dict[str, Any], metric: dict[str, Any], invalid: Any
) -> None:
    metric["cvssData"]["baseScore"] = invalid
    with pytest.raises(ValueError):
        extract_record(payload, CVE_ID)


# Вимагає словник даних і наявну числову оцінку.
def test_missing_score_and_cvss_data(
    payload: dict[str, Any], metric: dict[str, Any]
) -> None:
    del metric["cvssData"]["baseScore"]
    with pytest.raises(ValueError):
        extract_record(payload, CVE_ID)
    metric["cvssData"] = None
    with pytest.raises(ValueError):
        extract_record(payload, CVE_ID)


# Перевіряє поле варіанта лише під час побудови звіту.
@pytest.mark.parametrize("invalid", [None, "local", "", "REMOTE", 1, True, [], {}])
def test_invalid_rule_field(
    payload: dict[str, Any], metric: dict[str, Any], invalid: Any
) -> None:
    metric["cvssData"]["attackVector"] = invalid
    record = extract_record(payload, CVE_ID)
    with pytest.raises(ValueError, match="attackVector"):
        build_report(record, CVE_ID, 9)


# Зберігає оцінку, коли потрібне поле правила відсутнє.
def test_missing_rule_field(payload: dict[str, Any], metric: dict[str, Any]) -> None:
    del metric["cvssData"]["attackVector"]
    report = build_report(extract_record(payload, CVE_ID), CVE_ID, 9)
    assert report["decision"] == "insufficient_data"
    assert report["score"] == 9.8
    assert report["observed"] is None


# Відхиляє некоректні наявні метадані вибраної оцінки.
@pytest.mark.parametrize("field", ["version", "vectorString", "source"])
@pytest.mark.parametrize("invalid", [None, "", "  ", 31, False, []])
def test_invalid_optional_metadata(
    payload: dict[str, Any], metric: dict[str, Any], field: str, invalid: Any
) -> None:
    target = metric if field == "source" else metric["cvssData"]
    target[field] = invalid
    with pytest.raises(ValueError):
        extract_record(payload, CVE_ID)


# Дозволяє відсутні метадані, але відхиляє іншу версію CVSS.
def test_missing_metadata_and_wrong_version(
    payload: dict[str, Any], metric: dict[str, Any]
) -> None:
    metric["cvssData"]["version"] = "3.0"
    with pytest.raises(ValueError):
        extract_record(payload, CVE_ID)
    del metric["cvssData"]["version"]
    del metric["cvssData"]["vectorString"]
    del metric["source"]
    report = build_report(extract_record(payload, CVE_ID), CVE_ID, 9)
    assert report["cvss_version"] is None
    assert report["vector"] is None
    assert report["score_source"] is None
    assert report["decision"] == "other"


# Вибирає першу Primary, ігноруючи вміст інших словників.
def test_primary_selection(
    payload: dict[str, Any], cve: dict[str, Any], metric: dict[str, Any]
) -> None:
    primary = deepcopy(metric)
    primary["cvssData"].update(baseScore=5.0, attackVector="LOCAL")
    cve["metrics"]["cvssMetricV31"] = [
        {"type": "Secondary", "cvssData": None},
        primary,
        metric,
    ]
    report = build_report(extract_record(payload, CVE_ID), CVE_ID, 9)
    assert report["score"] == 5.0
    assert report["decision"] == "review"


# Без Primary вибирає першу оцінку без змішування джерел.
def test_first_fallback_and_same_source(
    payload: dict[str, Any], cve: dict[str, Any], metric: dict[str, Any]
) -> None:
    second = deepcopy(metric)
    metric["type"] = "Secondary"
    metric["cvssData"].update(baseScore=4.9, attackVector="LOCAL")
    second["type"] = "Secondary"
    second["cvssData"].update(baseScore=9.8, attackVector="NETWORK")
    cve["metrics"]["cvssMetricV31"] = [metric, second]
    report = build_report(extract_record(payload, CVE_ID), CVE_ID, 9)
    assert report["score"] == 4.9
    assert report["observed"] == "LOCAL"
    assert report["decision"] == "other"


# Не пропускає некоректну вибрану Primary заради іншої оцінки.
def test_invalid_primary_is_not_skipped(
    payload: dict[str, Any], cve: dict[str, Any], metric: dict[str, Any]
) -> None:
    metric["type"] = "Secondary"
    cve["metrics"]["cvssMetricV31"] = [metric, {"type": "Primary", "cvssData": None}]
    with pytest.raises(ValueError):
        extract_record(payload, CVE_ID)


# Аналіз не змінює відповідь і відокремлює вкладені дані.
def test_payload_is_not_mutated(payload: dict[str, Any]) -> None:
    original = deepcopy(payload)
    record = extract_record(payload, CVE_ID)
    report = build_report(record, CVE_ID, 9)
    assert payload == original
    payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0][
        "cvssData"
    ].update(baseScore=0, attackVector="LOCAL")
    assert build_report(record, CVE_ID, 9) == report


# Незмінність оцінки дозволяє уникнути повторної перевірки даних.
def test_extracted_metric_is_immutable(payload: dict[str, Any]) -> None:
    record = extract_record(payload, CVE_ID)
    with pytest.raises(FrozenInstanceError):
        record.metric.score = 0
    with pytest.raises(TypeError):
        record.metric.values["attackVector"] = "LOCAL"


# Некоректне поле іншого варіанта не впливає на поточний.
def test_only_requested_rule_field_is_validated(
    payload: dict[str, Any], metric: dict[str, Any]
) -> None:
    metric["cvssData"]["attackComplexity"] = []
    record = extract_record(payload, CVE_ID)
    assert build_report(record, CVE_ID, 9)["decision"] == "other"
    with pytest.raises(ValueError, match="attackComplexity"):
        build_report(record, CVE_ID, 2)


# Відхиляє bool та номери поза дозволеним діапазоном.
@pytest.mark.parametrize("invalid", [True, False, 0, 16, 9.0, "9", None])
def test_invalid_variant(invalid: Any) -> None:
    with pytest.raises(ValueError):
        build_report(None, CVE_ID, invalid)
