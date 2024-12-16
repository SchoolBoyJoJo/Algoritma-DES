import socket
import threading
from rsa_code import generate_key_pair, decrypt_rsa, encrypt_rsa
from des1 import decryption
import random

clients = {}  # Menyimpan informasi client: {socket: {"id": ..., "public_key": ...}}
public_key = None
private_key = None

def request_pka_public_key():
    host = "127.0.0.1"
    port = 6000

    try:
        pka_socket = socket.socket()
        pka_socket.connect((host, port))
        pka_socket.send(b"REQUEST_PKA_PUBLIC_KEY")
        response = pka_socket.recv(1024).decode()

        if not response:  # Validasi data kosong
            print("Received empty response from PKA.")
            return None

        e, n = map(int, response.split(","))
        return (e, n)
    except Exception as e:
        print(f"Error requesting PKA public key: {e}")
        return None

def request_public_key_from_pka(target_id):
    host = "127.0.0.1"
    port = 6000

    try:
        pka_socket = socket.socket()
        pka_socket.connect((host, port))

        # Kirim permintaan public key dengan ID target
        request_data = f"REQUEST_KEY:{target_id}"
        
        # Double enkripsi: 
        # Tahap 1: Enkripsi dengan private key server
        stage1_encrypted = encrypt_rsa(request_data, private_key)
        # Tahap 2: Enkripsi dengan public key PKA
        stage2_encrypted = encrypt_rsa(str(stage1_encrypted), pka_public_key)
        
        pka_socket.send(str(stage2_encrypted).encode())

        # Terima public key target
        response = pka_socket.recv(1024).decode()
        stage1_decrypted = decrypt_rsa(int(response), private_key)  # Tahap 1
        stage2_decrypted = decrypt_rsa(int(stage1_decrypted), pka_public_key)  # Tahap 2

        e, n = map(int, stage2_decrypted.split(","))
        return (e, n)
    except Exception as e:
        print(f"Error connecting to PKA: {e}")
        return None


def server_handshake(client_socket):
    try:
        # Tahap 1: Terima public key client, n1, dan ID client
        encrypted_data = client_socket.recv(1024).decode()
        decrypted_data = decrypt_rsa(int(encrypted_data), private_key)
        client_public_key, n1, client_id = decrypted_data.split("|")
        n1 = int(n1)

        print(f"Handshake request from client {client_id} with n1: {n1}")

        # Simpan public key client sementara
        client_key = request_public_key_from_pka(client_id)
        if not client_key:
            print(f"Failed to get public key for client {client_id}")
            return False, None, None

        # Generate n2 (angka acak baru untuk validasi server)
        n2 = random.randint(100000, 999999)

        # Tahap 2: Kirim public key client, n1, dan n2
        handshake_response = f"{client_public_key}|{n1}|{n2}"
        encrypted_response = encrypt_rsa(handshake_response, client_key)
        client_socket.send(str(encrypted_response).encode())

        # Tahap 3: Terima validasi akhir dari client
        validation_data = client_socket.recv(1024).decode()
        decrypted_validation = decrypt_rsa(int(validation_data), private_key)
        server_public_key, received_n2 = decrypted_validation.split("|")
        received_n2 = int(received_n2)

        # Validasi n2
        if received_n2 != n2:
            print(f"Handshake failed with client {client_id}: invalid n2")
            return False, None, None

        print(f"Handshake successful with client {client_id}")
        return True, client_key, client_id
    except Exception as e:
        print(f"Error during handshake: {e}")
        return False, None, None


def request_client_public_key(username):
    host = "127.0.0.1"
    port = 6000
    try:
        pka_socket = socket.socket()
        pka_socket.connect((host, port))
        pka_socket.send(f"REQUEST_KEY:{username}".encode())
        response = pka_socket.recv(1024).decode()
        pka_socket.close()
        e, n = map(int, response.split(","))
        return (e, n)
    except Exception as e:
        print(f"Error connecting to PKA: {e}")
        return None


def handle_client(client_socket, address, private_key):
    try:
        # Send username request to client
        client_socket.send(b"USERNAME_REQUEST")
        username = client_socket.recv(1024).decode()
        
        clients[client_socket] = {"username": username, "address": address}
        print(f"New client connected: {username} ({address})")

        # Receive the client's public key and n1
        data = client_socket.recv(1024).decode()
        e_client, n_client, n1 = map(int, data.split(","))
        
        # Generate n2
        n2 = random.randint(1000, 9999)
        
        # Send response with proper format
        response = f"{public_key[0]},{public_key[1]},{n1},{n2}"
        client_socket.send(response.encode())

        # Receive the encrypted DES key from the client
        encrypted_des_key = client_socket.recv(1024).decode()

        # Decrypt the DES key using the RSA private key of the server
        des_key = decrypt_rsa(int(encrypted_des_key), private_key)
        print(f"Decrypted DES key for {username}: {des_key}")

        # Decrypt and handle incoming messages from the client
        while True:
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
        print(f"Error handling client {client_id}: {e}")
    finally:
        # Hapus client saat terputus
        if client_socket in clients:
            print(f"Client {clients[client_socket]['username']} ({address}) disconnected.")
            del clients[client_socket]
        client_socket.close()

def server_program():
    global public_key, private_key, pka_public_key
    public_key, private_key = generate_key_pair()

    # Meminta public key PKA
    pka_public_key = request_pka_public_key()
    if not pka_public_key:
        print("Failed to get PKA public key. Exiting.")
        return

    # Simpan public key server di PKA
    pka_socket = socket.socket()
    pka_socket.connect(("127.0.0.1", 6000))
    pka_socket.send(f"STORE_KEY:server:{public_key[0]},{public_key[1]}".encode())
    pka_socket.close()

    host = socket.gethostname()
    port = 5000

    server_socket = socket.socket()
    server_socket.bind((host, port))
    server_socket.listen()
    print(f"Server is running on {host}:{port}...")

    while True:
        client_socket, address = server_socket.accept()
        threading.Thread(target=handle_client, args=(client_socket, address, private_key)).start()


if __name__ == '__main__':
    server_program()
