import csv
import hashlib
import json
import os
import sys
from datetime import datetime
from functools import wraps

# Додаємо шлях для імпорту спільного модуля
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import VARIANT_NUMBER  # noqa: E402

# Налаштування Варіанту 9
MIN_PASSWORD_LENGTH = 13
PERSONAL_SALT = str(VARIANT_NUMBER).zfill(5)
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
USERS_CSV = os.path.join(DATA_DIR, "users.csv")
LOG_JSON = os.path.join(DATA_DIR, "log.json")


class ValidationError(Exception):
    """Власний клас винятку для помилок валідації пароля."""
    pass


def ensure_data_dir() -> None:
    """Створює директорію data, якщо вона не існує."""
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)


def generate_hash(password: str, salt: str = "00000") -> str:
    """Генерує sha224 хеш пароля з сіллю."""
    if not password or not salt:
        raise ValueError("Пароль або сіль не можуть бути порожніми.")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(f"Пароль надто короткий (мінімум {MIN_PASSWORD_LENGTH} символів).")

    combined = password + salt
    # sha224 для Варіанту 9
    return hashlib.sha224(combined.encode("utf-8")).hexdigest()


def create_user(username: str, password: str) -> tuple[str, str]:
    """Створює кортеж користувача з хешованим паролем."""
    hash_value = generate_hash(password, PERSONAL_SALT)
    return (username, hash_value)


def create_users(users_list: tuple) -> None:
    """Записує список користувачів у CSV файл."""
    ensure_data_dir()
    try:
        with open(USERS_CSV, mode="w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(["username", "password_hash"])
            for user in users_list:
                try:
                    user_record = create_user(user[0], user[1])
                    writer.writerow(user_record)
                except ValidationError as e:
                    print(f"Помилка створення {user[0]}: {e}")
    except OSError as e:
        print(f"Помилка роботи з файлом {USERS_CSV}: {e}")


def read_users_db() -> list[dict]:
    """Зчитує базу користувачів з CSV."""
    db = []
    try:
        with open(USERS_CSV, mode="r", encoding="utf-8") as file:
            reader = csv.DictReader(file)
            for row in reader:
                db.append(row)
    except FileNotFoundError:
        print("База даних користувачів не знайдена.")
    return db


def log_event(func):
    """Декоратор для логування спроб авторизації в JSON."""

    @wraps(func)
    def wrapper(username: str, password: str, *args, **kwargs):
        ensure_data_dir()
        result = "failure"
        try:
            is_success = func(username, password, *args, **kwargs)
            if is_success:
                result = "success"
            return is_success
        finally:
            log_entry = {
                "event": "login",
                "user": username,
                "result": result,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "args": args,
                "kwargs": kwargs,
            }
            try:
                # Читаємо існуючі логи або створюємо новий список
                logs = []
                if os.path.exists(LOG_JSON):
                    with open(LOG_JSON, "r", encoding="utf-8") as f:
                        try:
                            logs = json.load(f)
                        except json.JSONDecodeError:
                            logs = []

                logs.append(log_entry)

                with open(LOG_JSON, "w", encoding="utf-8") as f:
                    json.dump(logs, f, indent=4)
            except OSError as e:
                print(f"Помилка запису логів: {e}")

    return wrapper


@log_event
def login(username: str, password: str) -> bool:
    """Перевіряє авторизацію користувача."""
    if not username or not password:
        raise ValueError("Логін та пароль є обов'язковими.")

    db = read_users_db()

    try:
        input_hash = generate_hash(password, PERSONAL_SALT)
    except ValidationError:
        return False  # Пароль не проходить базову валідацію, тому авторизація неможлива

    for user_record in db:
        if user_record["username"] == username and user_record["password_hash"] == input_hash:
            return True
    return False


def main() -> None:
    users_to_register = (
        ("admin", "SuperSecurePass123"),
        ("user1", "ValidPassForVar9"),
        ("guest", "Short123"),  # Викличе ValidationError (менше 13 символів)
        ("developer", "AnotherLongPassword"),
        ("", "ffff")
    )

    print("--- Реєстрація користувачів ---")
    create_users(users_to_register)

    print("\n--- База Даних (CSV) ---")
    db = read_users_db()
    for row in db:
        print(f"User: {row['username']:<15} | Hash: {row['password_hash']}")

    print("\n--- Спроби авторизації ---")
    try:
        print(f"Login admin: {login('admin', 'SuperSecurePass123')}")  # success
        print(f"Login user1 (wrong pass): {login('user1', 'WrongPassword123')}")  # failure
        print(f"Login unknown: {login('hacker', 'TryToHack12345')}")  # failure
    except ValueError as e:
        print(f"Помилка вводу: {e}")


if __name__ == "__main__":
    main()