import socket
import threading
import rsa
from des1 import encryption, decryption

clients = []
client_keys = {}  # Menyimpan kunci DES dari setiap client
private_key = None
public_key = None

def initialize_server():
    global private_key, public_key
    public_key, private_key = rsa.newkeys(512)

def request_public_key_from_pka():
    host = '127.0.0.1'  # IP PKA
    port = 6000         # Port PKA

    try:
        pka_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        pka_socket.connect((host, port))
        public_key_data = pka_socket.recv(1024).decode()
        pka_socket.close()
        print(f"Received public key from PKA: {public_key_data}")
        return public_key_data
    except Exception as e:
        print(f"Error connecting to PKA: {e}")
        return None

def handle_client(client_socket, client_address):
    try:
        while True:
            data = client_socket.recv(1024)
            if not data:
                break

            if data == b"REQUEST_PUBLIC_KEY":
                print(f"Client {client_address} requested public key.")
                public_key_data = request_public_key_from_pka()
                if public_key_data:
                    client_socket.send(public_key_data.encode())
                else:
                    print("Failed to fetch public key from PKA.")
                    client_socket.close()
                    break
            elif data.startswith(b"DES_KEY:"):
                print(f"Received DES key from {client_address}.")
                encrypted_key = data[len(b"DES_KEY:"):]
                des_key = rsa.decrypt(encrypted_key, private_key).decode()
                client_keys[client_socket] = des_key
                print(f"Decrypted DES key for {client_address}: {des_key}")
            else:
                des_key = client_keys.get(client_socket)
                if des_key:
                    decrypted_message = decryption(data.decode(), des_key)
                    print(f"Message from {client_address}: {decrypted_message}")
                else:
                    print(f"Error: DES key not found for {client_address}")
    except Exception as e:
        print(f"Error handling client {client_address}: {e}")
    finally:
        if client_socket in clients:
            clients.remove(client_socket)
        client_socket.close()

def server_program():
    initialize_server()
    host = socket.gethostname()
    port = 5000

    server_socket = socket.socket()
    server_socket.bind((host, port))
    server_socket.listen()
    print("Server is running...")

    while True:
        client_socket, address = server_socket.accept()
        print(f"Connection from {address}")
        clients.append(client_socket)
        threading.Thread(target=handle_client, args=(client_socket, address)).start()

if __name__ == '__main__':
    server_program()
