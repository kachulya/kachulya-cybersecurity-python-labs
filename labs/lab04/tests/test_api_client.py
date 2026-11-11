from typing import Any
from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import api_client

CVE_ID = "CVE-2099-10001"


# Створює контрольовану відповідь без справжнього HTTP-запиту.
@pytest.fixture
def response() -> Mock:
    result = Mock(spec=requests.Response)
    result.status_code = 200
    result.json.return_value = {"vulnerabilities": []}
    return result


# Не додає ключ для відсутнього або порожнього значення.
@pytest.mark.parametrize("key", [None, "", "   ", "\t\n"])
def test_headers_without_key(monkeypatch: pytest.MonkeyPatch, key: str | None) -> None:
    if key is not None:
        monkeypatch.setenv("NVD_API_KEY", key)
    assert api_client.build_headers() == {"Accept": "application/json"}


# Читає актуальний ключ під час виклику й очищає пробіли.
def test_headers_read_key_at_call_time(monkeypatch: pytest.MonkeyPatch) -> None:
    assert api_client.build_headers() == {"Accept": "application/json"}
    monkeypatch.setenv("NVD_API_KEY", "  fictional-test-key  ")
    assert api_client.build_headers() == {
        "Accept": "application/json",
        "apiKey": "fictional-test-key",
    }


# Звіряє адресу, параметри, таймаут і заборону перенаправлень.
@pytest.mark.parametrize("with_key", [False, True])
def test_fetch_uses_expected_request(
    monkeypatch: pytest.MonkeyPatch, response: Mock, with_key: bool
) -> None:
    expected_headers = {"Accept": "application/json"}
    if with_key:
        monkeypatch.setenv("NVD_API_KEY", "fictional-test-key")
        expected_headers["apiKey"] = "fictional-test-key"
    fake_get = Mock(return_value=response)
    monkeypatch.setattr(api_client.requests, "get", fake_get)
    assert api_client.fetch_response(CVE_ID) == {"vulnerabilities": []}
    fake_get.assert_called_once_with(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"cveId": CVE_ID},
        headers=expected_headers,
        timeout=(3.05, 10),
        allow_redirects=False,
    )
    response.raise_for_status.assert_called_once_with()
    response.json.assert_called_once_with()


# Приховує текст мережевих винятків і не повторює запит.
@pytest.mark.parametrize(
    "error, expected",
    [
        (requests.exceptions.Timeout, "час очікування"),
        (requests.exceptions.ConnectTimeout, "час очікування"),
        (requests.exceptions.ReadTimeout, "час очікування"),
        (requests.exceptions.ConnectionError, "з'єднання"),
        (requests.exceptions.SSLError, "з'єднання"),
        (requests.exceptions.RequestException, "виконання запиту"),
    ],
)
def test_network_failure_is_sanitized(
    monkeypatch: pytest.MonkeyPatch,
    error: type[requests.RequestException],
    expected: str,
) -> None:
    fake_get = Mock(side_effect=error("fictional-secret; private response body"))
    monkeypatch.setattr(api_client.requests, "get", fake_get)
    with pytest.raises(api_client.APIClientError, match=expected) as exc:
        api_client.fetch_response(CVE_ID)
    assert "fictional-secret" not in str(exc.value)
    assert "private response body" not in str(exc.value)
    fake_get.assert_called_once()


# HTTP-помилка не перетворюється на порожній результат пошуку.
@pytest.mark.parametrize("status_code", [400, 403, 404, 429, 500, 503])
def test_http_error(
    monkeypatch: pytest.MonkeyPatch, response: Mock, status_code: int
) -> None:
    response.status_code = status_code
    response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        "fictional-secret; private response body", response=response
    )
    monkeypatch.setattr(api_client.requests, "get", Mock(return_value=response))
    with pytest.raises(api_client.APIClientError, match=str(status_code)) as exc:
        api_client.fetch_response(CVE_ID)
    assert "fictional-secret" not in str(exc.value)
    response.json.assert_not_called()


# Відхиляє перенаправлення та будь-який успішний статус крім 200.
@pytest.mark.parametrize("status_code", [201, 204, 301, 302, 304, 307, 308])
def test_unexpected_status(
    monkeypatch: pytest.MonkeyPatch, response: Mock, status_code: int
) -> None:
    response.status_code = status_code
    monkeypatch.setattr(api_client.requests, "get", Mock(return_value=response))
    with pytest.raises(api_client.APIClientError, match=str(status_code)):
        api_client.fetch_response(CVE_ID)
    response.raise_for_status.assert_called_once_with()
    response.json.assert_not_called()


# Обробляє некоректний JSON без виведення тіла відповіді.
def test_invalid_response_json(monkeypatch: pytest.MonkeyPatch, response: Mock) -> None:
    response.json.side_effect = requests.exceptions.JSONDecodeError(
        "Invalid JSON", "{", 1
    )
    monkeypatch.setattr(api_client.requests, "get", Mock(return_value=response))
    with pytest.raises(api_client.APIClientError, match="JSON"):
        api_client.fetch_response(CVE_ID)


# Залишає семантичну перевірку даних модулю аналізу.
@pytest.mark.parametrize("decoded", [None, [], "text", 123])
def test_decoded_payload_is_not_validated_by_client(
    monkeypatch: pytest.MonkeyPatch, response: Mock, decoded: Any
) -> None:
    response.json.return_value = decoded
    monkeypatch.setattr(api_client.requests, "get", Mock(return_value=response))
    assert api_client.fetch_response(CVE_ID) == decoded


# Автоматична фікстура унеможливлює випадковий справжній запит.
def test_real_requests_are_disabled() -> None:
    assert not hasattr(requests.sessions.Session, "request")
