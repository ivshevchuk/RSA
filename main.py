import socket
import time

from RSA import generate_key_pair, encrypt_message, hack_rsa
from cryptography.hazmat.primitives import serialization

def main():
    # Генеруємо пару ключів для обох клієнтів
    private_key, public_key = generate_key_pair()

    # Зберігаємо приватний ключ у файлі
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Створюємо серверний сокет
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('localhost', 12345))
        s.listen()

        # Приймаємо підключення від клієнта 1
        conn, addr = s.accept()

        # Отримуємо повідомлення від клієнта 1
        message = conn.recv(512).decode()

        # Шифруємо повідомлення
        start = time.time()
        encrypted_message = encrypt_message(message, public_key)
        encrypted_time = time.time() - start
        print("Encoding time:", encrypted_time)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(('localhost', 12346))

            # Надсилаємо зашифроване повідомлення клієнту 2
            s.sendall(encrypted_message)

        #Взлом повідомлення
        start = time.time()
        hacked_message = hack_rsa(message, public_key)
        hacked_time = time.time() - start
        print("Hacked message:", hacked_message)
        print("Hacked time:", hacked_time)


if __name__ == "__main__":
    main()