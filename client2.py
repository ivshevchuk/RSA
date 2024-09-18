import socket
import time
from cryptography.hazmat.backends import default_backend
from RSA import decrypt_message
from cryptography.hazmat.primitives import serialization

def main():
    # Створюємо клієнтський сокет
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('localhost', 12346))
        s.listen()

        # Приймаємо підключення
        conn, addr = s.accept()

        # Отримуємо повідомлення від сервера
        encrypted_message = conn.recv(1024)

        print("Encrypted message: ", encrypted_message.hex())

        with open("private_key.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        start = time.time()
        decrypted_message = decrypt_message(encrypted_message, private_key)
        decrypted_time = time.time() - start
        print("Decrypted message:", decrypted_message)
        print("Decoding time:", decrypted_time)

if __name__ == "__main__":
    main()
