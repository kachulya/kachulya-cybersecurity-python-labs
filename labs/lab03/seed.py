"""Скрипт перевірки початкових даних і заповнення бази з JSON."""

import json
import sqlite3
import sys
from contextlib import closing
from pathlib import Path

from pydantic import ValidationError

from labs.lab03.database import BASE_DIR, get_connection, initialize_database
from labs.lab03.schemas import SeedData

SEED_FILE_PATH: Path = BASE_DIR / "data" / "seed.json"


def load_seed_data(file_path: Path = SEED_FILE_PATH) -> SeedData:
    """Прочитати та провалідувати JSON-файл із початковими даними."""
    if not file_path.exists():
        raise FileNotFoundError(f"Файл початкових даних не знайдено: {file_path}")
    raw_content = json.loads(file_path.read_text(encoding="utf-8"))
    return SeedData.model_validate(raw_content)


def seed_database(file_path: Path = SEED_FILE_PATH) -> bool:
    """Заповнити порожню базу початковими категоріями та записами в одній транзакції."""
    initialize_database()
    seed_data = load_seed_data(file_path)

    with closing(get_connection()) as connection:
        categories_count = connection.execute(
            "SELECT COUNT(*) FROM categories"
        ).fetchone()[0]
        records_count = connection.execute("SELECT COUNT(*) FROM records").fetchone()[0]

        if categories_count > 0 or records_count > 0:
            print(
                f"База даних уже містить дані (категорій: {categories_count}, "
                f"записів: {records_count}). Повторне заповнення пропущено."
            )
            return False

        with connection:
            connection.executemany(
                "INSERT INTO categories (id, name) VALUES (?, ?)",
                [(cat.id, cat.name) for cat in seed_data.categories],
            )
            connection.executemany(
                """
                INSERT INTO records (code, title, category_id, value, status)
                VALUES (?, ?, ?, ?, ?)
                """,
                [
                    (rec.code, rec.title, rec.category_id, rec.value, rec.status)
                    for rec in seed_data.records
                ],
            )

    print(
        f"Базу успішно заповнено: додано {len(seed_data.categories)} категорії "
        f"та {len(seed_data.records)} записів."
    )
    return True


def main() -> None:
    """Точка входу для запуску початкового заповнення з командного рядка."""
    try:
        seed_database()
    except (FileNotFoundError, json.JSONDecodeError, ValidationError) as exc:
        print(f"Помилка перевірки початкових даних seed.json: {exc}", file=sys.stderr)
        sys.exit(1)
    except sqlite3.Error as exc:
        print(
            f"Помилка бази даних під час заповнення (транзакцію скасовано): {exc}",
            file=sys.stderr,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
