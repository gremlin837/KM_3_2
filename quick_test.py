from auth_tests.auth_module import AuthenticationSystem


auth = AuthenticationSystem()


print("quick tests")


# 1. Создание пользователя
print("\n1. Создание пользователя:")
success, msg = auth.create_account("ivan", "Iv@n12345", is_admin=False)
print(f"   {msg}")

# 2. Вход (требуется смена пароля)
print("\n2. Первичный вход:")
success, msg, account = auth.authenticate("ivan", "Iv@n12345")
print(f"   {msg}")

# 3. Смена пароля
if account:
    success, msg = auth.change_password_after_auth(account, "N3wIv@n67890")
    print(f"\n3. Смена пароля: {msg}")

# 4. Вход с новым паролем
print("\n4. Вход с новым паролем:")
success, msg, _ = auth.authenticate("ivan", "N3wIv@n67890")
print(f"   {msg}")

# 5. Проверка блокировки
print("\n5. Проверка блокировки (3 попытки):")
auth.create_account("test", "T3st@Pass", is_admin=False)
for i in range(3):
    success, msg, _ = auth.authenticate("test", "wrong")
    print(f"   Попытка {i+1}: {msg}")

# 6. Проверка валидации пароля
print("\n6. Проверка валидации пароля:")
success, msg = auth.create_account("weak", "12345", is_admin=False)
print(f"   Слабый пароль '12345': {msg}")

print("finished")