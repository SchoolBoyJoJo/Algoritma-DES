import socket
from rsa_code import generate_key_pair, encrypt_rsa
from des1 import encryption

public_key = None
private_key = None


def send_key_to_pka(username):
    host = "127.0.0.1"
    port = 6000

    try:
        pka_socket = socket.socket()
        pka_socket.connect((host, port))
        pka_socket.send(f"STORE_KEY:{username}:{public_key[0]},{public_key[1]}".encode())
        response = pka_socket.recv(1024).decode()
        print(response)
        pka_socket.close()
    except Exception as e:
        print(f"Error connecting to PKA: {e}")


def request_server_key():
    host = "127.0.0.1"
    port = 6000

    try:
        pka_socket = socket.socket()
        pka_socket.connect((host, port))
        pka_socket.send(b"REQUEST_KEY:server")
        response = pka_socket.recv(1024).decode()
        pka_socket.close()
        e, n = map(int, response.split(","))
        return (e, n)
    except Exception as e:
        print(f"Error connecting to PKA: {e}")
        return None


def client_program():
    global public_key, private_key
    public_key, private_key = generate_key_pair()

    username = input("Enter your username: ")
    send_key_to_pka(username)  # Kirim public key ke PKA

    server_key = request_server_key()
    if not server_key:
        print("Failed to get server key. Exiting.")
        return

    host = socket.gethostname()
    port = 5000

    client_socket = socket.socket()
    client_socket.connect((host, port))

    # Kirim username ke server
    username_request = client_socket.recv(1024).decode()
    if username_request == "USERNAME_REQUEST":
        client_socket.send(username.encode())

    # Kirim DES key terenkripsi ke server
    des_key = "abcdefgh"
    encrypted_key = encrypt_rsa(des_key, server_key)
    client_socket.send(str(encrypted_key).encode())

    # Kirim pesan
    while True:
        message = input(" -> ")
        if message.lower() == "exit":
            client_socket.close()
            break

        encrypted_message, _, _ = encryption(message, des_key)
        client_socket.send(encrypted_message.encode())


if __name__ == '__main__':
    client_program()
