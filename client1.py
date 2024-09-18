import socket

def main():
    # Введіть повідомлення для шифрування
    message = input("Enter the message to be encrypted: ")

    # Підключаємося до сервера
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(('localhost', 12345))

        # Відправляємо повідомлення на сервер
        s.sendall(message.encode())

if __name__ == "__main__":
    main()
