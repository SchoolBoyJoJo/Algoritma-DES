import socket
import threading
from rsa_code import generate_key_pair, decrypt_rsa
from des1 import decryption
import random

clients = {}  # Menyimpan informasi client (socket -> {"username": ..., "address": ...})
private_key = None
public_key = None

def request_pka_public_key():
    host = "127.0.0.1"
    port = 6000

    try:
        pka_socket = socket.socket()
        pka_socket.connect((host, port))
        pka_socket.send(b"REQUEST_PKA_PUBLIC_KEY")
        response = pka_socket.recv(1024).decode()
        e, n = map(int, response.split(","))
        return (e, n)
    except Exception as e:
        print(f"Error requesting PKA public key: {e}")
        return None
    finally:
        pka_socket.close()

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

def request_client_public_key(username):
    host = "127.0.0.1"
    port = 6000
    try:
        # First, get PKA's public key
        pka_public_key = request_pka_public_key()
        if not pka_public_key:
            print("Failed to get PKA public key")
            return None

        pka_socket = socket.socket()
        pka_socket.connect((host, port))
        pka_socket.send(f"REQUEST_KEY:{username}".encode())
        response = pka_socket.recv(1024).decode()
        pka_socket.close()

        if response == "Key not found.":
            print("Client key not found in PKA")
            return None

        # Decrypt the key using PKA's public key
        from rsa_code import decrypt_rsa_to_str  # Use the new function
        decrypted_key = decrypt_rsa_to_str(response, pka_public_key)
        
        # Parse the decrypted key
        e, n = map(int, decrypted_key.split(","))
        return (e, n)
    except Exception as e:
        print(f"Error connecting to PKA: {e}")
        return None

def handle_client(client_socket, address, private_key):
    try:
        # Send username request to client
        client_socket.send(b"USERNAME_REQUEST")
        username = client_socket.recv(1024).decode()
        
        if not username:
            print("Empty username received")
            return
            
        clients[client_socket] = {"username": username, "address": address}
        print(f"New client connected: {username} ({address})")

        # Receive the client's public key and n1
        data = client_socket.recv(1024).decode()
        if not data:
            print("Empty handshake data received")
            return
            
        try:
            e_client, n_client, n1 = map(int, data.split(","))
        except ValueError as e:
            print(f"Invalid handshake data format: {data}")
            return
            
        # Generate n2
        n2 = random.randint(1000, 9999)
        
        # Send response with proper format
        response = f"{public_key[0]},{public_key[1]},{n1},{n2}"
        client_socket.send(response.encode())

        # Receive the encrypted DES key from the client
        encrypted_des_key = client_socket.recv(1024).decode()

        # Decrypt the DES key using the RSA private key of the server
        des_key = decrypt_rsa(encrypted_des_key, private_key)
        print(f"Decrypted DES key for {username}: {des_key}")

        # Decrypt and handle incoming messages from the client
        while True:
            encrypted_message = client_socket.recv(1024).decode()
            if not encrypted_message:
                break

            # Decrypt the message using the DES key
            decrypted_message = decryption(encrypted_message, des_key)
            print(f"Message from {username}: {decrypted_message}")

            # Broadcast the decrypted message to all connected clients except the sender
            for client, info in clients.items():
                if client != client_socket:
                    try:
                        client.send(f"{username}: {decrypted_message}".encode())
                    except Exception as e:
                        print(f"Error sending message to {info['username']}: {e}")

    except Exception as e:
        print(f"Error handling client {address}: {e}")
    finally:
        if client_socket in clients:
            print(f"Client {clients[client_socket]['username']} ({address}) disconnected.")
            del clients[client_socket]
        client_socket.close()
        
def server_program():
    global public_key, private_key
    public_key, private_key = generate_key_pair()
    send_key_to_pka()  # Send server's public key to PKA

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