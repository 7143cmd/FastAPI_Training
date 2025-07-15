from cryptography.fernet import Fernet


def main(secret_str):

    with open("key.key", 'rb') as key_file:
        key = key_file.read()

    # print(key)

    cipher = Fernet(key)

    cached = cipher.encrypt(bytes(secret_str, encoding='utf-8'))
    ready = cipher.decrypt(cached)
    return cached.decode()


# print(main('007'))