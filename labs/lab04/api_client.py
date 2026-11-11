import os
from typing import Any

import requests

from labs.lab04.config import API_URL, REQUEST_TIMEOUT


# Позначає контрольовану помилку отримання відповіді API.
class APIClientError(RuntimeError):
    """Помилка клієнта без секретів і тіла відповіді."""


# Формує заголовки, читаючи ключ лише під час виклику.
def build_headers() -> dict[str, str]:
    """Повернути Accept і необов'язковий очищений apiKey."""
    headers = {"Accept": "application/json"}
    api_key = os.getenv("NVD_API_KEY", "").strip()
    if api_key:
        headers["apiKey"] = api_key
    return headers


# Виконує один запит без перенаправлень і повторів.
def fetch_response(cve_id: str) -> Any:
    """Отримати JSON NVD або підняти APIClientError."""
    try:
        response = requests.get(
            API_URL,
            params={"cveId": cve_id},
            headers=build_headers(),
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
        )
        response.raise_for_status()
    except requests.exceptions.Timeout:
        raise APIClientError("Перевищено час очікування відповіді NVD.") from None
    except requests.exceptions.ConnectionError:
        raise APIClientError("Не вдалося встановити з'єднання з NVD.") from None
    except requests.exceptions.HTTPError as exc:
        status_code = exc.response.status_code if exc.response is not None else None
        detail = f" (HTTP {status_code})" if isinstance(status_code, int) else ""
        raise APIClientError(f"HTTP-помилка NVD{detail}.") from None
    except requests.exceptions.RequestException:
        raise APIClientError("Помилка виконання запиту до NVD.") from None

    if response.status_code != 200:
        raise APIClientError(f"Неочікуваний статус NVD: HTTP {response.status_code}.")

    try:
        return response.json()
    except requests.exceptions.JSONDecodeError:
        raise APIClientError("Відповідь NVD містить некоректний JSON.") from None
