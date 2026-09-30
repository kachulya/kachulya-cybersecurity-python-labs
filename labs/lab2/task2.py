import argparse
import csv
import json
import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

# Необхідні заголовки безпеки
REQUIRED_HEADERS = {
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options"
}


def setup_logging(log_level: str):
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    if not isinstance(numeric_level, int):
        raise TypeError(f"Invalid log level: {log_level}")
    logging.basicConfig(
        level=numeric_level,
        format='[%(levelname)s] %(message)s'
    )


def check_software_leaks(headers: dict, url: str):
    # Регулярний вираз для пошуку витоку версій (наприклад, Apache/2.4.41)
    version_pattern = re.compile(r'[a-zA-Z]+\/[\d\.]+')
    leaks = []

    for target_header in ["Server", "X-Powered-By"]:
        if target_header in headers and version_pattern.search(headers[target_header]):
            leaks.append(target_header)
            logger.warning(f"[LEAK] {url} leaks info in '{target_header}': {headers[target_header]}")
    return leaks


def audit_headers(input_file: Path, output_file: Path, strict: bool):
    logger.info(f"Auditing HTTP response headers from {input_file}...")

    if not input_file.exists():
        logger.error(f"File not found: {input_file}")
        return

    try:
        with open(input_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        logger.error(f"Failed to read JSON file: {e}")
        return

    results = []

    # Виправлено помилку AttributeError: тепер ми ітеруємося по списку об'єктів
    for item in data:
        url = item.get("url", "Unknown")
        headers = item.get("headers", {})

        # Захист на випадок, якщо поле headers виявиться порожнім або не словником
        if not isinstance(headers, dict):
            headers = {}

        present_headers = set(headers.keys())
        missing_headers = REQUIRED_HEADERS - present_headers

        # Перевірка витоків
        leaks = check_software_leaks(headers, url)

        # Розрахунок підсумкового індексу безпеки (Score)
        score = 100

        # Якщо увімкнено прапорець --strict, штраф більший
        penalty = 25 if strict else 15
        score -= len(missing_headers) * penalty
        score -= len(leaks) * 10
        score = max(0, score)

        if score >= 90:
            status = "PASS"
        elif score >= 60:
            status = "WARN"
        else:
            status = "FAIL"

        missing_str = ", ".join(missing_headers) if missing_headers else "None"

        results.append({
            "Target Resource": url,
            "Security Score": f"{score}/100",
            "Status": status,
            "Missing Security Headers": missing_str
        })

        # Згідно з вимогами, завжди логуємо відсутні заголовки
        if missing_headers:
            logger.warning(f"Resource {url} is missing headers: {missing_str}")

    # Створюємо директорію для вихідного файлу, якщо її немає
    output_file.parent.mkdir(parents=True, exist_ok=True)

    # Збереження результатів аудиту у CSV-файл
    try:
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["Target Resource", "Security Score", "Status",
                                                   "Missing Security Headers"])
            writer.writeheader()
            writer.writerows(results)
        logger.info(f"Header audit report generated at {output_file}")
    except OSError as e:
        logger.error(f"Failed to write output CSV: {e}")


def main():
    # Додано парсер аргументів командного рядка (argparse)
    parser = argparse.ArgumentParser(description="HTTP Headers Security Auditor")
    parser.add_argument("--headers-file", type=Path, required=True, help="Path to JSON file with HTTP headers")
    parser.add_argument("--output-csv", type=Path, required=True, help="Path to output CSV report")
    parser.add_argument("--strict", action="store_true", help="Apply strict scoring")
    parser.add_argument("--log-level", type=str, default="INFO", help="Logging level (INFO, WARNING, ERROR)")

    args = parser.parse_args()

    setup_logging(args.log_level)
    audit_headers(args.headers_file, args.output_csv, args.strict)


if __name__ == "__main__":
    main()

#python -m labs.lab2.task2 --headers-file labs/lab2/data/headers.json --output-csv labs/lab2/data/headers_audit.csv --strict