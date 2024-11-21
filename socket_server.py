import socket
import threading
from rsa_code import generate_key_pair, decrypt_rsa
from des1 import decryption

clients = {}  # Menyimpan informasi client (socket -> {"username": ..., "address": ...})
private_key = None
public_key = None


def send_key_to_pka():
    host = "127.0.0.1"
    port = 6000

    try:
        pka_socket = socket.socket()
        pka_socket.connect((host, port))
        pka_socket.send(f"STORE_KEY:server:{public_key[0]},{public_key[1]}".encode())
        response = pka_socket.recv(1024).decode()
        print(response)
        pka_socket.close()
    except Exception as e:
        print(f"Error connecting to PKA: {e}")


def handle_client(client_socket, address):
    try:
        # Minta username dari client
        client_socket.send(b"USERNAME_REQUEST")
        username = client_socket.recv(1024).decode()
        print(f"New client connected: {username} ({address})")

        # Simpan informasi client
        clients[client_socket] = {"username": username, "address": address}

        # Terima DES key dari client
        encrypted_key = int(client_socket.recv(1024).decode())
        des_key = decrypt_rsa(encrypted_key, private_key)
        print(f"Decrypted DES key for {username}: {des_key}")

        while True:
            # Terima dan decrypt pesan
            encrypted_message = client_socket.recv(1024).decode()
            if not encrypted_message:
                break
            decrypted_message = decryption(encrypted_message, des_key)
            print(f"Message from {username}: {decrypted_message}")

            # Kirim pesan ke semua client
            for client, info in clients.items():
                if client != client_socket:
                    client.send(f"{username}: {decrypted_message}".encode())
    except Exception as e:
        print(f"Error handling client {address}: {e}")
    finally:
        # Hapus client saat terputus
        if client_socket in clients:
            print(f"Client {clients[client_socket]['username']} ({address}) disconnected.")
            del clients[client_socket]
        client_socket.close()


def server_program():
    global public_key, private_key
    public_key, private_key = generate_key_pair()
    send_key_to_pka()  # Kirim public key server ke PKA

    host = socket.gethostname()
    port = 5000

    server_socket = socket.socket()
    server_socket.bind((host, port))
    server_socket.listen()
    print(f"Server is running on {host}:{port}...")

    while True:
        client_socket, address = server_socket.accept()
        threading.Thread(target=handle_client, args=(client_socket, address)).start()


if __name__ == '__main__':
    server_program()
