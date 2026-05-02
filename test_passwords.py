from auth_tests.auth_module import AuthenticationSystem


def test_password_contains_username():

    print("ТЕСТ: Пароли")


    auth = AuthenticationSystem()

    # Очищаем возможные старые аккаунты
    auth.accounts.clear()

    test_cases = [
        # (username, password, expected_result, comment)
        ("alice", "alice123", False, "содержит 'alice' - должен быть ОТКЛОНЁН"),
        ("alice", "Alice123", False, "содержит 'alice' (разный регистр) - должен быть ОТКЛОНЁН"),
        ("alice", "123alice", False, "содержит 'alice' - должен быть ОТКЛОНЁН"),
        ("alice", "Alicia@789", True, "НЕ содержит 'alice' - должен быть ПРИНЯТ"),
        ("bob", "bob", False, "совпадает полностью - должен быть ОТКЛОНЁН"),
        ("bob", "bob123", False, "содержит 'bob' - должен быть ОТКЛОНЁН"),
        ("bob", "Bobby@123", False, "содержит 'bob' - должен быть ОТКЛОНЁН"),
        ("charlie", "Charlie123", False, "содержит 'charlie' - должен быть ОТКЛОНЁН"),
        ("elena", "Secret@Pass123", True, "НЕ содержит 'elena' - должен быть ПРИНЯТ"),
        ("peter", "SecureP@ss456", True, "НЕ содержит 'peter' - должен быть ПРИНЯТ"),
    ]

    all_passed = True

    for username, password, expected, comment in test_cases:
        success, msg = auth.create_account(username, password, is_admin=False)

        # expected = False (success = False)
        # expected = True (success = True)
        is_correct = (success == expected)

        if is_correct:
            print(f" {username}: '{password}'")
            print(f"   Результат: {'ОТКЛОНЁН' if not success else 'ПРИНЯТ'} (верно)")
        else:
            all_passed = False
            print(f" {username}: '{password}'")
            print(f"   Ожидание: {'ОТКЛОНЁН' if not expected else 'ПРИНЯТ'}")
            print(f"   Реальность: {'ОТКЛОНЁН' if not success else 'ПРИНЯТ'}")
            print(f"   Сообщение: {msg}")
            print(f"   Комментарий: {comment}")

        # Удаляем аккаунт после теста
        if username in auth.accounts:
            del auth.accounts[username]

        print()


    if all_passed:
        print(" ВСЕ ТЕСТЫ ПРОЙДЕНЫ")
    else:
        print(" ЕСТЬ ОШИБКИ")



if __name__ == "__main__":
    test_password_contains_username()