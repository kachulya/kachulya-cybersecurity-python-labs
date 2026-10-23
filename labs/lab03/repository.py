"""Шар доступу до даних (Repository) із параметризованими SQL-запитами."""

import logging
import sqlite3
from contextlib import closing
from typing import Any

from labs.lab03.database import get_connection
from labs.lab03.schemas import CategoryCreate, RecordCreate, RecordReplace

logger = logging.getLogger(__name__)


class RepositoryError(Exception):
    """Базовий виняток шару роботи з базою даних."""


class NotFoundError(RepositoryError):
    """Запитуваний ресурс (запис або категорія) не існує."""


class ConflictError(RepositoryError):
    """Конфлікт унікальності або спроба видалити непорожню категорію."""


def _row_to_category(row: sqlite3.Row) -> dict[str, Any]:
    """Перетворити рядок SQLite на словник категорії."""
    return {"id": row["id"], "name": row["name"]}


def _row_to_record(row: sqlite3.Row) -> dict[str, Any]:
    """Перетворити рядок SQLite на словник запису разом із category_name."""
    return {
        "id": row["id"],
        "code": row["code"],
        "title": row["title"],
        "category_id": row["category_id"],
        "value": float(row["value"]),
        "status": row["status"],
        "category_name": row["category_name"],
    }


def list_categories() -> list[dict[str, Any]]:
    """Отримати список усіх категорій за зростанням id."""
    try:
        with closing(get_connection()) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                "SELECT id, name FROM categories ORDER BY id ASC"
            ).fetchall()
            return [_row_to_category(row) for row in rows]
    except sqlite3.Error as exc:
        logger.exception("Помилка отримання списку категорій")
        raise RepositoryError("Не вдалося отримати список категорій") from exc


def create_category(data: CategoryCreate) -> dict[str, Any]:
    """Створити нову категорію в базі даних."""
    try:
        with closing(get_connection()) as connection:
            connection.row_factory = sqlite3.Row
            with connection:
                cursor = connection.execute(
                    "INSERT INTO categories (name) VALUES (?)",
                    (data.name,),
                )
                category_id = cursor.lastrowid
            row = connection.execute(
                "SELECT id, name FROM categories WHERE id = ?",
                (category_id,),
            ).fetchone()
            return _row_to_category(row)
    except sqlite3.IntegrityError as exc:
        logger.warning("Конфлікт під час створення категорії '%s': %s", data.name, exc)
        raise ConflictError(f"Категорія з назвою '{data.name}' уже існує") from exc
    except sqlite3.Error as exc:
        logger.exception("Помилка бази даних під час створення категорії")
        raise RepositoryError("Не вдалося створити категорію") from exc


def delete_category(category_id: int) -> None:
    """Видалити порожню категорію за її ідентифікатором."""
    try:
        with closing(get_connection()) as connection:
            exists = connection.execute(
                "SELECT 1 FROM categories WHERE id = ?",
                (category_id,),
            ).fetchone()
            if exists is None:
                raise NotFoundError(f"Категорію з id={category_id} не знайдено")

            with connection:
                connection.execute(
                    "DELETE FROM categories WHERE id = ?",
                    (category_id,),
                )
    except NotFoundError:
        raise
    except sqlite3.IntegrityError as exc:
        logger.warning(
            "Спроба видалити непорожню категорію id=%s: %s", category_id, exc
        )
        raise ConflictError(
            f"Неможливо видалити категорію з id={category_id}, оскільки вона містить записи"
        ) from exc
    except sqlite3.Error as exc:
        logger.exception("Помилка бази даних під час видалення категорії")
        raise RepositoryError("Не вдалося видалити категорію") from exc


def _fetch_record_by_id(
    connection: sqlite3.Connection, record_id: int
) -> dict[str, Any] | None:
    """Допоміжна функція отримання запису з назвою категорії за id."""
    row = connection.execute(
        """
        SELECT r.id, r.code, r.title, r.category_id, r.value, r.status,
               c.name AS category_name
        FROM records r
        JOIN categories c ON c.id = r.category_id
        WHERE r.id = ?
        """,
        (record_id,),
    ).fetchone()
    return _row_to_record(row) if row is not None else None


def get_record_by_id(record_id: int) -> dict[str, Any]:
    """Отримати один запис за його id або викликати NotFoundError."""
    try:
        with closing(get_connection()) as connection:
            connection.row_factory = sqlite3.Row
            record = _fetch_record_by_id(connection, record_id)
            if record is None:
                raise NotFoundError(f"Запис із id={record_id} не знайдено")
            return record
    except NotFoundError:
        raise
    except sqlite3.Error as exc:
        logger.exception("Помилка бази даних під час отримання запису id=%s", record_id)
        raise RepositoryError("Не вдалося отримати запис") from exc


def list_records(
    category_id: int | None = None,
    status: str | None = None,
    min_value: float | None = None,
    q: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Отримати список записів із фільтрами та пагінацією."""
    conditions: list[str] = []
    params: list[Any] = []

    if category_id is not None:
        conditions.append("r.category_id = ?")
        params.append(category_id)
    if status is not None:
        conditions.append("r.status = ?")
        params.append(status)
    if min_value is not None:
        conditions.append("r.value >= ?")
        params.append(min_value)
    if q is not None:
        conditions.append("instr(r.title, ?) > 0")
        params.append(q)

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    query = f"""
        SELECT r.id, r.code, r.title, r.category_id, r.value, r.status,
               c.name AS category_name
        FROM records r
        JOIN categories c ON c.id = r.category_id
        {where_clause}
        ORDER BY r.id ASC
        LIMIT ? OFFSET ?
    """
    params.extend([limit, offset])

    try:
        with closing(get_connection()) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(query, params).fetchall()
            return [_row_to_record(row) for row in rows]
    except sqlite3.Error as exc:
        logger.exception("Помилка бази даних під час вибірки записів")
        raise RepositoryError("Не вдалося отримати список записів") from exc


def create_record(data: RecordCreate) -> dict[str, Any]:
    """Створити новий запис у базі даних."""
    try:
        with closing(get_connection()) as connection:
            connection.row_factory = sqlite3.Row
            category_exists = connection.execute(
                "SELECT 1 FROM categories WHERE id = ?",
                (data.category_id,),
            ).fetchone()
            if category_exists is None:
                raise NotFoundError(f"Категорію з id={data.category_id} не знайдено")

            with connection:
                cursor = connection.execute(
                    """
                    INSERT INTO records (code, title, category_id, value, status)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (data.code, data.title, data.category_id, data.value, data.status),
                )
                record_id = int(cursor.lastrowid)

            record = _fetch_record_by_id(connection, record_id)
            if record is None:
                raise RepositoryError("Не вдалося прочитати створений запис")
            return record
    except NotFoundError:
        raise
    except sqlite3.IntegrityError as exc:
        logger.warning(
            "Конфлікт під час створення запису code='%s': %s", data.code, exc
        )
        raise ConflictError(f"Запис із кодом '{data.code}' уже існує") from exc
    except sqlite3.Error as exc:
        logger.exception("Помилка бази даних під час створення запису")
        raise RepositoryError("Не вдалося створити запис") from exc


def replace_record(record_id: int, data: RecordReplace) -> dict[str, Any]:
    """Повністю оновити змінювані поля наявного запису за його id."""
    try:
        with closing(get_connection()) as connection:
            connection.row_factory = sqlite3.Row
            record_exists = connection.execute(
                "SELECT 1 FROM records WHERE id = ?",
                (record_id,),
            ).fetchone()
            if record_exists is None:
                raise NotFoundError(f"Запис із id={record_id} не знайдено")

            category_exists = connection.execute(
                "SELECT 1 FROM categories WHERE id = ?",
                (data.category_id,),
            ).fetchone()
            if category_exists is None:
                raise NotFoundError(f"Категорію з id={data.category_id} не знайдено")

            with connection:
                connection.execute(
                    """
                    UPDATE records
                    SET code = ?, title = ?, category_id = ?, value = ?, status = ?
                    WHERE id = ?
                    """,
                    (
                        data.code,
                        data.title,
                        data.category_id,
                        data.value,
                        data.status,
                        record_id,
                    ),
                )

            updated = _fetch_record_by_id(connection, record_id)
            if updated is None:
                raise RepositoryError("Не вдалося прочитати оновлений запис")
            return updated
    except NotFoundError:
        raise
    except sqlite3.IntegrityError as exc:
        logger.warning(
            "Конфлікт під час оновлення запису id=%s (code='%s'): %s",
            record_id,
            data.code,
            exc,
        )
        raise ConflictError(f"Запис із кодом '{data.code}' уже існує") from exc
    except sqlite3.Error as exc:
        logger.exception("Помилка бази даних під час оновлення запису id=%s", record_id)
        raise RepositoryError("Не вдалося оновити запис") from exc


def delete_record(record_id: int) -> None:
    """Видалити запис за його ідентифікатором."""
    try:
        with closing(get_connection()) as connection:
            exists = connection.execute(
                "SELECT 1 FROM records WHERE id = ?",
                (record_id,),
            ).fetchone()
            if exists is None:
                raise NotFoundError(f"Запис із id={record_id} не знайдено")

            with connection:
                connection.execute(
                    "DELETE FROM records WHERE id = ?",
                    (record_id,),
                )
    except NotFoundError:
        raise
    except sqlite3.Error as exc:
        logger.exception("Помилка бази даних під час видалення запису id=%s", record_id)
        raise RepositoryError("Не вдалося видалити запис") from exc


def bulk_create_records(items: list[RecordCreate]) -> list[dict[str, Any]]:
    """Пакетно створити записи в межах однієї транзакції."""
    try:
        with closing(get_connection()) as connection:
            connection.row_factory = sqlite3.Row
            created_ids: list[int] = []

            with connection:
                for item in items:
                    category_exists = connection.execute(
                        "SELECT 1 FROM categories WHERE id = ?",
                        (item.category_id,),
                    ).fetchone()
                    if category_exists is None:
                        raise NotFoundError(
                            f"Категорію з id={item.category_id} не знайдено"
                        )

                    cursor = connection.execute(
                        """
                        INSERT INTO records (code, title, category_id, value, status)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            item.code,
                            item.title,
                            item.category_id,
                            item.value,
                            item.status,
                        ),
                    )
                    created_ids.append(int(cursor.lastrowid))

            created_records: list[dict[str, Any]] = []
            for rec_id in created_ids:
                record = _fetch_record_by_id(connection, rec_id)
                if record is not None:
                    created_records.append(record)
            return created_records
    except NotFoundError:
        raise
    except sqlite3.IntegrityError as exc:
        logger.warning("Конфлікт унікальності під час пакетного створення: %s", exc)
        raise ConflictError(
            "Пакет містить дублікат коду запису (всередині пакета або в базі даних)"
        ) from exc
    except sqlite3.Error as exc:
        logger.exception("Помилка бази даних під час пакетного створення записів")
        raise RepositoryError("Не вдалося зберегти пакет записів") from exc
