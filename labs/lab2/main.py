import sys
from datetime import timedelta

# Змінено шлях імпорту на lab02
from labs.lab2.task1 import Admin, User, UserAccount


def run_demo():
    print("=== Демонстрація Завдання 1 ===")

    # 1. Створення звичайного користувача
    user = User("developer1", "dev@example.com")
    user.set_password("SecurePass123")
    print(f"Створено користувача: {user}")

    # Спроба задати недійсний email
    try:
        user.email = "bad_email@.com"
    except ValueError as e:
        print(f"Помилка зміни email: {e}")

    # 2. Створення адміністратора
    admin = Admin("sysadmin", "admin@domain.com")
    admin.grant_permission("FULL_ACCESS")
    print(f"Створено адміністратора: {admin}")

    # 3. Використання UserAccount (композиція)
    account = UserAccount(user)

    print("\n--- Спроби входу ---")
    # Передача username в метод login
    account.login("developer1", "WrongPass", "192.168.1.50")
    account.login("developer1", "SecurePass123", "192.168.1.50")
    print(f"Автентифіковано після правильного пароля: {account.is_authenticated()}")

    # Демонстрація завершення сеансу за таймаутом
    print("\n--- Демонстрація таймауту сеансу ---")
    if account["session"]:
        # Віднімаємо час, що перевищує SESSION_TIMEOUT_SEC (900)
        account["session"].last_activity -= timedelta(seconds=1000)
        print(f"Автентифіковано після 1000 секунд простою: {account.is_authenticated()}")

    # 4. Завершення сеансу (logout)
    print("\n--- Вихід із системи ---")
    account.login("developer1", "SecurePass123", "192.168.1.50") # Вхід для демонстрації виходу
    account.logout()
    print(f"Автентифіковано після виходу: {account.is_authenticated()}")

    print("\n--- Журнал аудиту ---")
    account["audit_log"].show_all()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "demo":
        run_demo()
    else:
        # Виправлена команда запуску для lab2
        print("Для демонстрації ООП запустіть: python -m labs.lab2.main demo")
