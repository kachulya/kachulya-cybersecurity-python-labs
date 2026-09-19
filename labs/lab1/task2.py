users = {
    "cloud_architect": {"role": "cloud_security", "clearance": 4, "department": "Cloud", "active": True},
    "devops_engineer": {"role": "devops", "clearance": 3, "department": "DevOps", "active": True},
    "qa_tester": {"role": "quality_assurance", "clearance": 2, "department": "QA", "active": True},
    "partner_access": {"role": "partner", "clearance": 2, "department": "Partnership", "active": True},
    "migrated_user": {"role": "migrated", "clearance": 1, "department": "Migration", "active": False}
}

resources = [
    ("cloud_configs", 4), ("deployment_pipelines", 3), ("test_environments", 2),
    ("partner_apis", 2), ("infrastructure_code", 4), ("shared_resources", 1),
    ("container_registry", 3), ("secrets_vault", 4), ("build_artifacts", 2),
    ("public_endpoints", 1)
]

security_levels = ("Development", "Staging", "Production", "Critical Infrastructure")
blocked_users = {"migrated_user", "container_breach", "pipeline_compromise"}

# Додаємо тестового користувача, якого немає в базі, щоб перевірити умову "DENY (User not found)"
test_users_to_check = list(users.keys()) + ["unknown_hacker"]


def check_access():
    print("--- Ресурси системи ---")
    for res_name, res_level in resources:
        level_name = security_levels[res_level - 1]
        print(f"Ресурс: {res_name:<20} | Рівень: {level_name}")

    print("\n--- Журнал контролю доступу ---")

    for username in test_users_to_check:
        for res_name, res_level in resources:
            status = evaluate_access(username, res_level)
            print(f"user=[{username}] resource=[{res_name}] -> {status}")


def evaluate_access(username: str, resource_level: int) -> str:
    if username not in users:
        return "DENY (User not found)"

    if username in blocked_users:
        return "DENY (User is blocked)"

    user_data = users[username]

    if not user_data["active"]:
        return "DENY (Account inactive)"

    if user_data["clearance"] >= resource_level:
        return "ALLOW"
    else:
        return "DENY (Insufficient clearance)"


if __name__ == "__main__":
    check_access()