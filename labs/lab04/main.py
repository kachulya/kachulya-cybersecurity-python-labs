import argparse
import json
import re
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from labs.lab04 import api_client
from labs.lab04.analysis import build_report, extract_record
from labs.lab04.config import CVE_PATTERN
from shared.student import VARIANT_NUMBER


# Перевіряє повний збіг ідентифікатора із шаблоном CVE.
def parse_cve_id(value: str) -> str:
    """Перевірити формат CVE без перевірки року існування."""
    if re.fullmatch(CVE_PATTERN, value) is None:
        raise argparse.ArgumentTypeError(
            "Очікується CVE-РРРР-НОМЕР, наприклад CVE-2099-10001."
        )
    return value


# Читає локальний JSON без звернення до мережі.
def load_response(path: str | Path) -> Any:
    """Прочитати відповідь NVD з JSON-файла у UTF-8."""
    with Path(path).open(encoding="utf-8") as source:
        return json.load(source)


# Виводить повідомлення помилки й повертає код завершення.
def _error(message: str, code: int = 1) -> int:
    """Надрукувати пояснення помилки лише у stderr."""
    print(message, file=sys.stderr)
    return code


# Поєднує аргументи, отримання даних і побудову звіту.
def main(argv: Sequence[str] | None = None) -> int:
    """Вивести JSON або повідомлення помилки; повернути код завершення."""
    if type(VARIANT_NUMBER) is not int or not 1 <= VARIANT_NUMBER <= 15:
        return _error(
            "Помилка: номер варіанта має бути цілим числом від 1 до 15.",
            code=2,
        )

    parser = argparse.ArgumentParser(
        description="Аналіз CVE з NVD API або локального JSON-файла."
    )
    parser.add_argument(
        "--cve", required=True, type=parse_cve_id, help="Ідентифікатор CVE"
    )
    parser.add_argument(
        "--input", type=Path, help="Локальна відповідь NVD у форматі JSON"
    )
    args = parser.parse_args(argv)

    try:
        payload = (
            load_response(args.input)
            if args.input is not None
            else api_client.fetch_response(args.cve)
        )
        record = extract_record(payload, args.cve)
        report = build_report(record, args.cve, VARIANT_NUMBER)
    except api_client.APIClientError as exc:
        return _error(f"Помилка отримання даних: {exc}")
    except json.JSONDecodeError:
        return _error("Помилка: локальний файл містить некоректний JSON.")
    except UnicodeError:
        return _error("Помилка: локальний файл повинен мати кодування UTF-8.")
    except OSError:
        return _error("Помилка: не вдалося прочитати локальний файл.")
    except ValueError as exc:
        return _error(f"Помилка перевірки даних: {exc}")

    print(json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
