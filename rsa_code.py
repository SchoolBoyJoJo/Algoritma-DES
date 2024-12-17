import random

def is_prime(num):
    if num < 2:
        return False
    for i in range(2, int(num ** 0.5) + 1):
        if num % i == 0:
            return False
    return True

def generate_large_prime(start=100, end=1000):
    prime = random.randint(start, end)
    while not is_prime(prime):
        prime = random.randint(start, end)
    return prime

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def modular_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def generate_key_pair():
    p = generate_large_prime()
    q = generate_large_prime()
    while q == p:  # Ensure p and q are different
        q = generate_large_prime()

    n = p * q
    phi = (p - 1) * (q - 1)

    # Choose e (public key) that is coprime to phi
    e = random.randint(2, phi - 1)
    while gcd(e, phi) != 1:
        e = random.randint(2, phi - 1)

    # Calculate d (private key) as modular inverse of e mod phi
    d = modular_inverse(e, phi)

    return (e, n), (d, n)

def encrypt_rsa(plain_text, public_key):
    """
    Encrypt a message using RSA.
    Supports both string input.
    """
    e, n = public_key
    encrypted = [str(pow(ord(char), e, n)) for char in str(plain_text)]
    return ",".join(encrypted)

def decrypt_rsa(cipher_text, private_key):
    """
    Decrypt RSA-encrypted messages, supporting comma-separated values.
    """
    d, n = private_key
    encrypted_values = map(int, cipher_text.split(","))
    decrypted = ''.join([chr(pow(value, d, n)) for value in encrypted_values])
    return decrypted

def decrypt_rsa_to_str(cipher_text, public_key):
    """
    Decrypt an RSA-encrypted message using public key.
    """
    e, n = public_key
    encrypted_values = map(int, cipher_text.split(","))
    decrypted = ''.join([chr(pow(value, e, n)) for value in encrypted_values])
    return decrypted