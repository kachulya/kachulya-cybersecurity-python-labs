import sys
from labs.lab2.task1 import User, Admin, UserAccount


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
    account.login("WrongPass", "192.168.1.50")
    account.login("SecurePass123", "192.168.1.50")
    print(f"Автентифіковано: {account.is_authenticated()}")

    # 4. Завершення сеансу
    account.logout()

    print("\n--- Журнал аудиту ---")
    account["audit_log"].show_all()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "demo":
        run_demo()
    else:
        print("Для демонстрації ООП запустіть: python -m labs.lab2.main demo")