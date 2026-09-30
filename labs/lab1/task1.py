import os
import random
import sys

# Додаємо шлях для імпорту спільного модуля
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

# Вхідні дані Варіанту 9 (константи пишемо великими літерами)
PASSWORDS = [
    "Digital@F0r3nsics",
    "plain",
    "Encrypt10n@Key",
    "member",
    "Security@Audit2023",
    "regular",
    "Hack3r@D3fense",
    "ordinary",
    "Threat@Intel",
    "usual",
    "qpwoeiru",
    "qqq"
]

CRITERIA = {
    "min_length": 8,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}

FORBIDDEN_PASSWORDS = {"plain", "member", "regular", "ordinary", "usual", "user"}


def analyze_passwords() -> None:
    """Аналізує список паролів, генерує дублікати та виводить результати."""
    print(f"--- Аналіз паролів | {STUDENT_NAME}, {GROUP_NAME}, Варіант {VARIANT_NUMBER} ---\n")

    # Робимо копію, щоб не мутувати оригінальну глобальну змінну
    current_passwords = PASSWORDS.copy()

    # Генерація дублікатів
    indices = [random.randint(0, len(current_passwords) - 1) for _ in range(3)]
    for idx in indices:
        current_passwords.append(current_passwords[idx])

    print(f"{'Пароль':<20} | {'Статус':<15}")
    print("-" * 38)

    for pw in current_passwords:
        status = evaluate_password(pw, current_passwords)
        print(f"{pw:<20} | {status:<15}")


def evaluate_password(pw: str, pw_list: list[str]) -> str:
    """Оцінює надійність пароля за заданими критеріями."""
    min_length = CRITERIA["min_length"]

    # Перевіряємо наявність конкретних символів
    has_digit = any(c.isdigit() for c in pw)
    has_upper = any(c.isupper() for c in pw)
    has_special = any(not c.isalnum() for c in pw)

    # Заборонений
    if pw in FORBIDDEN_PASSWORDS or len(pw) < min_length:
        return "Заборонений"

    # Скільки з трьох додаткових критеріїв виконано (від 0 до 3)
    criteria_score = sum((has_digit, has_upper, has_special))
    is_unique = pw_list.count(pw) == 1

    # Дуже сильний та Сильний (всі 3 вимоги виконані)
    if criteria_score == 3:
        if len(pw) >= min_length + 4 and is_unique:
            return "Дуже сильний"
        return "Сильний"

    # Середній (виконано хоча б 2 вимоги з 3-х)
    if criteria_score == 2:
        return "Середній"

    # Слабкий (виконано 1 або 0 додаткових вимог)
    return "Слабкий"


if __name__ == "__main__":
    analyze_passwords()
