import random
from math import gcd

# Miller-Rabin untuk cek bilangan prima
def is_prime(n, k=5):  
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2

    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits):
    while True:
        prime = random.getrandbits(bits)
        if is_prime(prime):
            return prime

def generate_key_pair(bits=2048):
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    while p == q:
        q = generate_prime(bits // 2)

    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    if gcd(e, phi) != 1:
        raise ValueError("e and phi(n) are not coprime")

    def mod_inverse(a, m):
        m0, x0, x1 = m, 0, 1
        while a > 1:
            q = a // m
            m, a = a % m, m
            x0, x1 = x1 - q * x0, x0
        return x1 + m0 if x1 < 0 else x1

    d = mod_inverse(e, phi)
    return (e, n), (d, n)

def encrypt_rsa(plaintext, public_key):
    e, n = public_key
    plaintext_int = int.from_bytes(plaintext.encode(), 'big')
    return pow(plaintext_int, e, n)

def decrypt_rsa(ciphertext, private_key):
    d, n = private_key
    plaintext_int = pow(ciphertext, d, n)
    try:
        return plaintext_int.to_bytes((plaintext_int.bit_length() + 7) // 8, 'big').decode()
    except UnicodeDecodeError:
        raise ValueError("Decrypted plaintext is not valid UTF-8.")
