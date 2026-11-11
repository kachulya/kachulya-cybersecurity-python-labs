import json
import subprocess
import sys
from pathlib import Path
from textwrap import dedent
from typing import Any
from unittest.mock import Mock

import pytest

from labs.lab04 import api_client, main

CVE_ID = "CVE-2099-10001"
SAMPLE_PATH = Path(__file__).resolve().parents[1] / "data" / "nvd_sample.json"


# Перевіряє читання UTF-8 та відсутність мережі в локальному режимі.
def test_local_run(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake_fetch = Mock(side_effect=AssertionError("Локальний режим звернувся до API"))
    monkeypatch.setattr(api_client, "fetch_response", fake_fetch)
    assert main.main(["--cve", CVE_ID, "--input", str(SAMPLE_PATH)]) == 0
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert report["variant"] == 9
    assert report["decision"] == "other"
    assert report["rule"] == {
        "threshold": 5.0,
        "field": "attackVector",
        "expected": "LOCAL",
    }
    assert captured.err == ""
    fake_fetch.assert_not_called()


# Перевіряє взаємодію CLI зі справжнім аналізом відповіді клієнта.
def test_api_mode(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    payload: dict[str, Any],
) -> None:
    fake_fetch = Mock(return_value=payload)
    monkeypatch.setattr(api_client, "fetch_response", fake_fetch)
    assert main.main(["--cve", CVE_ID]) == 0
    fake_fetch.assert_called_once_with(CVE_ID)
    assert json.loads(capsys.readouterr().out)["decision"] == "other"


# Недостатність даних і порожній пошук завершуються успішним звітом.
@pytest.mark.parametrize(
    "payload, expected",
    [
        ({"vulnerabilities": []}, "not_found"),
        ({"vulnerabilities": [{"cve": {"id": CVE_ID}}]}, "insufficient_data"),
        (
            {"vulnerabilities": [{"cve": {"id": CVE_ID, "vulnStatus": "Rejected"}}]},
            "rejected",
        ),
    ],
)
def test_data_states_are_success(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    payload: dict[str, Any],
    expected: str,
) -> None:
    monkeypatch.setattr(api_client, "fetch_response", Mock(return_value=payload))
    assert main.main(["--cve", CVE_ID]) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert json.loads(captured.out)["decision"] == expected


# Невалідні аргументи дають код 2 без завантаження даних.
@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["--cve", "cve-2099-10001"],
        ["--cve", "CVE-2099-123"],
        ["--cve", "CVE-99-12345"],
        ["--cve", "CVE-2099-10001\n"],
        ["--cve", "CVE-２０９９-10001"],
        ["--cve", "prefix-CVE-2099-10001"],
        ["--cve", "CVE-2099-10001suffix"],
        ["--cve", CVE_ID, "--variant", "1"],
        ["--cve", CVE_ID, "--api-url", "https://example.com"],
    ],
)
def test_invalid_arguments(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], argv: list[str]
) -> None:
    fake_fetch = Mock()
    monkeypatch.setattr(api_client, "fetch_response", fake_fetch)
    with pytest.raises(SystemExit) as exc:
        main.main(argv)
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err
    fake_fetch.assert_not_called()


# Шаблон CVE не встановлює обмежень на існування року.
@pytest.mark.parametrize("cve_id", ["CVE-0000-0000", "CVE-2099-123456789"])
def test_cve_year_is_not_validated(cve_id: str) -> None:
    assert main.parse_cve_id(cve_id) == cve_id


# Некоректний номер варіанта завершує роботу перед отриманням даних.
@pytest.mark.parametrize("variant", [True, False, 0, 16, 9.0, "9", None])
def test_invalid_variant(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], variant: Any
) -> None:
    monkeypatch.setattr(main, "VARIANT_NUMBER", variant)
    fake_fetch = Mock()
    monkeypatch.setattr(api_client, "fetch_response", fake_fetch)
    assert main.main(["--cve", CVE_ID]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "варіанта" in captured.err
    fake_fetch.assert_not_called()


# Використовує імпортований номер варіанта замість прихованої константи.
def test_variant_is_imported(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(main, "VARIANT_NUMBER", 1)
    assert main.main(["--cve", CVE_ID, "--input", str(SAMPLE_PATH)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["variant"] == 1
    assert report["decision"] == "review"


# Помилки файла дають stderr і код 1 без трасування.
@pytest.mark.parametrize(
    "content, expected", [(None, "прочитати"), (b"{", "JSON"), (b"\xff", "UTF-8")]
)
def test_file_errors(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    content: bytes | None,
    expected: str,
) -> None:
    path = tmp_path / "response.json"
    if content is not None:
        path.write_bytes(content)
    assert main.main(["--cve", CVE_ID, "--input", str(path)]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert expected in captured.err
    assert "Traceback" not in captured.err


# Локальна відповідь повинна відповідати запитаному ідентифікатору.
def test_local_cve_mismatch(capsys: pytest.CaptureFixture[str]) -> None:
    assert main.main(["--cve", "CVE-2099-99999", "--input", str(SAMPLE_PATH)]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "не збігається" in captured.err


# Некоректна структура даних не формує успішний JSON-звіт.
def test_invalid_payload(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        api_client, "fetch_response", Mock(return_value={"vulnerabilities": None})
    )
    assert main.main(["--cve", CVE_ID]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "перевірки даних" in captured.err


# Мережева помилка формує лише безпечне повідомлення у stderr.
def test_api_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        api_client,
        "fetch_response",
        Mock(side_effect=api_client.APIClientError("HTTP 429")),
    )
    assert main.main(["--cve", CVE_ID]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "HTTP 429" in captured.err
    assert "Traceback" not in captured.err


# Зберігає українські символи у виведеному JSON без екранування.
def test_unicode_output(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], payload: dict[str, Any]
) -> None:
    payload["vulnerabilities"][0]["cve"]["descriptions"][0]["value"] = (
        "Перевірка Unicode"
    )
    path = tmp_path / "response.json"
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    assert main.main(["--cve", CVE_ID, "--input", str(path)]) == 0
    assert "Перевірка Unicode" in capsys.readouterr().out


# Імпорт модулів не читає даних і не запускає програму.
def test_import_has_no_side_effects() -> None:
    script = dedent("""
        from pathlib import Path
        from unittest.mock import patch
        import requests

        with (
            patch.object(requests.sessions.Session, "request", side_effect=AssertionError("HTTP")),
            patch.object(requests, "get", side_effect=AssertionError("HTTP")),
            patch.object(Path, "open", side_effect=AssertionError("File read")),
            patch.object(Path, "read_text", side_effect=AssertionError("File read")),
            patch("builtins.print", side_effect=AssertionError("Output")),
        ):
            import labs.lab04.api_client
            import labs.lab04.analysis
            import labs.lab04.main
    """)
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=Path(__file__).resolve().parents[3],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=15,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    assert result.stderr == ""


# Перевіряє справжній пакетний запуск і передавання коду завершення.
def test_module_entrypoint() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "labs.lab04.main",
            "--cve",
            CVE_ID,
            "--input",
            str(SAMPLE_PATH),
        ],
        cwd=Path(__file__).resolve().parents[3],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=15,
        check=False,
    )
    assert result.returncode == 0
    assert result.stderr == ""
    assert json.loads(result.stdout)["decision"] == "other"
