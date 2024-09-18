from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import sympy

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_message(message, public_key):
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt_message(ciphertext, private_key):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode()
    return plaintext


def hack_rsa(ciphertext, public_key):
    n = public_key.public_numbers().n  # Отримуємо модуль (n) з публічного ключа
    factors = factorize(n)             # Факторизуємо модуль на прості множники
    p, q = factors[0], factors[1]       # Отримуємо прості множники p та q
    phi = (p - 1) * (q - 1)             # Обчислюємо значення функції Ейлера (phi)

    e = public_key.public_numbers().e  # Отримуємо публічну експоненту (e)
    d = sympy.mod_inverse(e, phi)       # Вираховуємо приватний ключ (d)

    decrypted_message = decrypt(ciphertext, d, n)  # Розшифровуємо повідомлення
    return decrypted_message

def factorize(n):
    return sympy.factorint(n)

def decrypt(ciphertext, d, n):
    # Розшифруємо повідомлення за допомогою приватного ключа (d) та модуля (n)
    return pow(ciphertext, d, n)