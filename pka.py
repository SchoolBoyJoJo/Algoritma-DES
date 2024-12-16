import socket
import threading
from rsa_code import generate_key_pair, encrypt_rsa, decrypt_rsa

# Dictionary to store public keys (format: id -> (e, n))
public_keys = {}

# PKA's RSA keys
pka_public_key, pka_private_key = generate_key_pair()

def handle_request(client_socket):
    try:
        data = client_socket.recv(1024).decode()
        if data == "REQUEST_PKA_PUBLIC_KEY":
            key_str = f"{pka_public_key[0]},{pka_public_key[1]}"
            print(f"Sending PKA public key: {key_str}")
            client_socket.send(key_str.encode())
            
        elif data.startswith("STORE_KEY:"):
            client_id, key = data[len("STORE_KEY:"):].split(":")
            e, n = map(int, key.split(","))
            public_keys[client_id] = (e, n)
            print(f"Stored public key for ID {client_id}.")
            client_socket.send(b"Key stored successfully.")
            
        elif data.startswith("REQUEST_KEY:"):
            target_id = data[len("REQUEST_KEY:"):]
            if target_id in public_keys:
                target_key = public_keys[target_id]
                key_str = f"{target_key[0]},{target_key[1]}"
                print(f"Sending key for {target_id}: {key_str}")
                # Send the key directly without encryption
                client_socket.send(key_str.encode())
            else:
                client_socket.send(b"Key not found.")
    except Exception as e:
        print(f"Error handling request: {e}")
    finally:
        client_socket.close()

def pka_program():
    host = "127.0.0.1"
    port = 6000

    server_socket = socket.socket()
    server_socket.bind((host, port))
    server_socket.listen()
    print(f"PKA is running on {host}:{port}...")
    print(f"PKA public key: {pka_public_key}")

    while True:
        client_socket, _ = server_socket.accept()
        threading.Thread(target=handle_request, args=(client_socket,)).start()

if __name__ == '__main__':
    pka_program()