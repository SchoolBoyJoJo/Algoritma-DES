import socket
from rsa_code import generate_key_pair, encrypt_rsa
from des1 import encryption
import random

public_key = None
private_key = None

def double_encrypt(message, client_private_key, server_public_key):
    encrypted_with_client = encrypt_rsa(message, client_private_key) 
    double_encrypted = encrypt_rsa(encrypted_with_client, server_public_key)
    return double_encrypted

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
        # First, get PKA's public key
        pka_public_key = request_pka_public_key()
        if not pka_public_key:
            print("Failed to get PKA public key")
            return None

        pka_socket = socket.socket()
        pka_socket.connect((host, port))
        request = "REQUEST_KEY:server"
        print(f"Requesting server key from PKA...")
        pka_socket.send(request.encode())
        
        response = pka_socket.recv(1024).decode()
        pka_socket.close()

        if response == "Key not found.":
            print("Server key not found in PKA")
            return None
            
        # Decrypt the key using PKA's public key
        from rsa_code import decrypt_rsa_to_str  # Use the new function
        try:
            # Attempt to decrypt and parse the key
            decrypted_key = decrypt_rsa_to_str(response, pka_public_key)
            
            # Parse the decrypted key
            e, n = map(int, decrypted_key.split(","))
            print("Successfully received and decrypted server key")
            return (e, n)
        except Exception as e:
            print(f"Error parsing server key: {e}")
            return None
            
    except Exception as e:
        print(f"Error connecting to PKA: {e}")
        return None

def client_handshake(client_socket, client_key):
    n1 = random.randint(1000, 9999) 
    
    message = f"{client_key[0]},{client_key[1]},{n1}"
    client_socket.send(message.encode())
    
    # Receive response from server
    response = client_socket.recv(1024).decode()
    if response:
        try:
            e, n, n1_received, n2 = map(int, response.split(","))
            if int(n1_received) == n1:
                print("Handshake successful!")
                return n2
            else:
                print("N1 verification failed")
                return None
        except ValueError as e:
            print(f"Error: Invalid handshake response format: {e}")
            return None
    return None

def client_program():
    global public_key, private_key
    public_key, private_key = generate_key_pair()

    host = socket.gethostname()
    port = 5000
    
    try:
        client_socket = socket.socket()
        client_socket.connect((host, port))
    except Exception as e:
        print(f"Error connecting to server: {e}")
        return

    try:
        username_request = client_socket.recv(1024).decode()
        if username_request == "USERNAME_REQUEST":
            username = input("Enter your username: ")
            client_socket.send(username.encode())
            
            # First store our key
            print("Storing public key in PKA...")
            send_key_to_pka(username)
            
            # Small delay to ensure key is stored
            import time
            time.sleep(1)
    except Exception as e:
        print(f"Error in username exchange: {e}")
        client_socket.close()
        return

    # Get server key
    server_key = request_server_key()
    if not server_key:
        print("Failed to get server key. Exiting.")
        client_socket.close()
        return

    print("Proceeding with handshake...")
    n2 = client_handshake(client_socket, public_key)
    if not n2:
        print("Handshake failed. Exiting.")
        client_socket.close()
        return

    # send encrypted DES key to the server after successful handshake
    des_key = "abcdefgh"  
    encrypted_des_key = encrypt_rsa(des_key, server_key) 
    client_socket.send(str(encrypted_des_key).encode())

    # chatting
    while True:
        message = input(" -> ")
        if message.lower() == "exit":
            break

        # Enkripsi dua tahap
        double_encrypted_message = double_encrypt(message, private_key, server_key)
        client_socket.send(double_encrypted_message.encode())

    print("Closing connection.")
    client_socket.close()


if __name__ == '__main__':
    client_program()
