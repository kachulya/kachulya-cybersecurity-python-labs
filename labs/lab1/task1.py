import random
import sys
import os

# Додаємо шлях для імпорту спільного модуля
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from shared.student import STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER

# Вхідні дані Варіанту 9
passwords = [
    "Digital@F0r3nsics", "plain", "Encrypt10n@Key", "member",
    "Security@Audit2023", "regular", "Hack3r@D3fense", "ordinary",
    "Threat@Intel", "usual"
]
criteria = {
    "min_length": 8,
    "require_digits": True,
    "require_upper": True,
    "require_special": True
}
forbidden_passwords = {"plain", "member", "regular", "ordinary", "usual", "user"}


def analyze_passwords():
    print(f"--- Аналіз паролів | {STUDENT_NAME}, {GROUP_NAME}, Варіант {VARIANT_NUMBER} ---\n")

    # Генерація дублікатів
    indices = [random.randint(0, len(passwords) - 1) for _ in range(3)]
    for idx in indices:
        passwords.append(passwords[idx])

    print(f"{'Пароль':<20} | {'Статус':<15}")
    print("-" * 38)

    for pw in passwords:
        status = evaluate_password(pw, passwords)
        print(f"{pw:<20} | {status:<15}")


def evaluate_password(pw: str, pw_list: list) -> str:
    min_length = criteria["min_length"]
    has_digit = any(c.isdigit() for c in pw)
    has_upper = any(c.isupper() for c in pw)
    has_special = any(not c.isalnum() for c in pw)

    # Критерій: Заборонений
    if pw in forbidden_passwords or len(pw) < min_length:
        return "Заборонений"

    all_criteria_met = has_digit and has_upper and has_special
    some_criteria_met = has_digit or has_upper or has_special or any(c.islower() for c in pw)
    is_unique = pw_list.count(pw) == 1

    # Критерій: Дуже сильний та Сильний
    if all_criteria_met:
        if len(pw) >= min_length + 4 and is_unique:
            return "Дуже сильний"
        else:
            return "Сильний"

    # Критерій: Середній та Слабкий
    if some_criteria_met:
        return "Середній"

    return "Слабкий"


if __name__ == "__main__":
    analyze_passwords()