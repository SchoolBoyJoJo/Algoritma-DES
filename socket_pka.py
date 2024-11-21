import socket
import random
import string
import threading

# Database sederhana untuk menyimpan ID dan key
clients_db = {}

def generate_key():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=8))

def handle_client(connection, address):
    try:
        connection.sendall(b"Welcome to PKA. Please enter the menu you want:\n")
        pka_menu = connection.recv(1024).decode().strip()

        if pka_menu == '1':  # Key for the client itself
            connection.sendall(b"Please enter your 6-digit ID:\n")
            client_id = connection.recv(1024).decode().strip()

            # Check if the client_id exists
            if client_id in clients_db:
                public_key = clients_db[client_id]
                connection.sendall(f"Your public key is: {public_key}\n".encode())
            else:
                new_key = generate_key()
                clients_db[client_id] = new_key
                connection.sendall(f"New public key generated: {new_key}\n".encode())

        elif pka_menu == '2':  # Request key for another client
            connection.sendall(b"Please enter the 6-digit ID to get the key:\n")
            client_id = connection.recv(1024).decode().strip()

            # Return the key if exists
            if client_id in clients_db:
                public_key = clients_db[client_id]
                connection.sendall(f"This Client's public key is: {public_key}\n".encode())
            else:
                connection.sendall(b"This ID does not belong to any client.\n")
    except Exception as e:
        print(f"Error with client {address}: {e}")
    finally:
        connection.close()


def start_pka():
    host=socket.gethostname()
    port=5555
    pka_socket = socket.socket()
    pka_socket.bind((host, port))
    pka_socket.listen(5)
    print(f"PKA started on {host}:{port}")

    while True:
        client_socket, client_address = pka_socket.accept()
        threading.Thread(target=handle_client, args=(client_socket, client_address)).start()

if __name__ == "__main__":
    start_pka()
