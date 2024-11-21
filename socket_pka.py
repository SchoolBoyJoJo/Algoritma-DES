import socket
import random
import string
import threading

# Database sederhana untuk menyimpan ID dan key
clients_db = {}

def generate_key():
    """Generate random 8-character DES key."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=8))

def handle_client(connection, address):
    """Handle incoming client requests for key."""
    try:
        connection.sendall(b"Welcome to PKA. Please enter your 6-digit ID:\n")
        client_id = connection.recv(1024).decode().strip()
        
        # Validasi ID
        if len(client_id) != 6 or not client_id.isdigit():
            connection.sendall(b"Invalid ID. Please use a 6-digit numeric ID.\n")
            connection.close()
            return

        # Generate atau ambil existing key untuk client
        if client_id in clients_db:
            public_key = clients_db[client_id]
            connection.sendall(b"Your existing public key is: " + public_key.encode() + b"\n")
        else:
            public_key = generate_key()
            clients_db[client_id] = public_key
            connection.sendall(b"Your new public key is: " + public_key.encode() + b"\n")

    except Exception as e:
        print(f"Error with client {address}: {e}")
    finally:
        connection.close()

def start_pka(host='127.0.0.1', port=5555):
    """Start the PKA server."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)
    print(f"PKA started on {host}:{port}")

    while True:
        client_socket, client_address = server.accept()
        threading.Thread(target=handle_client, args=(client_socket, client_address)).start()

if __name__ == "__main__":
    start_pka()
