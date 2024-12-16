import socket
from rsa_code import generate_key_pair, encrypt_rsa
from des1 import encryption
import random

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

        print(f"Received response from PKA: '{response}'")  # Tambahkan log untuk melihat respons

        # Validasi respons yang diterima
        if not response.strip():  # Jika respons kosong atau hanya spasi
            print("Error: Received empty or invalid response from PKA.")
            return None

        # Menghapus karakter spasi atau newline yang tidak diinginkan
        response = response.strip()

        # Pastikan format data benar dan bisa dipisahkan
        try:
            e, n = map(int, response.split(","))
            return (e, n)
        except ValueError as ve:
            print(f"Error: Invalid format in response from PKA. {ve}")
            return None
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
        # Tahap 1: Enkripsi dengan private key client
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


def client_handshake(client_socket, server_key, client_id):
    n1 = random.randint(100000, 999999)

    # Kirim public key server, n1, dan ID client
    handshake_data = f"{public_key[0]},{public_key[1]}|{n1}|{client_id}"
    encrypted_data = encrypt_rsa(handshake_data, server_key)
    client_socket.send(str(encrypted_data).encode())

    # Terima respon dari server
    response = client_socket.recv(1024).decode()
    decrypted_response = decrypt_rsa(int(response), private_key)
    server_public_key, received_n1, n2 = decrypted_response.split("|")

    if int(received_n1) != n1:
        print("Handshake failed: Invalid n1")
        return False

    # Kirim validasi akhir dengan public key server dan n2
    validation_data = f"{server_public_key}|{n2}"
    encrypted_validation = encrypt_rsa(validation_data, server_key)
    client_socket.send(str(encrypted_validation).encode())

    return True


def client_handshake(client_socket, client_key):
    n1 = random.randint(1000, 9999)  # Generate a random number n1
    
    # Send our (client's) public key and n1 to server
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

    # Connect first
    host = socket.gethostname()
    port = 5000
    client_socket = socket.socket()
    client_socket.connect((host, port))

    # Wait for username request
    username_request = client_socket.recv(1024).decode()
    if username_request == "USERNAME_REQUEST":
        username = input("Enter your username: ")
        client_socket.send(username.encode())
        send_key_to_pka(username)  # Send public key to PKA
    
    # Get server key
    server_key = request_server_key()
    if not server_key:
        print("Failed to get server key. Exiting.")
        client_socket.close()
        return

    # Perform handshake
    n2 = client_handshake(client_socket, public_key)  # Send our public key, not server's
    if not n2:
        print("Handshake failed. Exiting.")
        client_socket.close()
        return

    # Step 5: Send encrypted DES key to the server after successful handshake
    des_key = "abcdefgh"  # For this example, you may generate or input a dynamic DES key
    encrypted_des_key = encrypt_rsa(des_key, server_key)  # Encrypt DES key with server's public key
    client_socket.send(str(encrypted_des_key).encode())  # Send encrypted DES key to the server

    # Step 6: Start chatting after successful handshake
    while True:
        message = input(" -> ")
        if message.lower() == "exit":
            break

        # Step 7: Encrypt message using the DES key
        encrypted_message, _, _ = encryption(message, des_key)  # Use your existing encryption function
        client_socket.send(encrypted_message.encode())  # Send encrypted message

    # Step 8: Close the connection when done
    print("Closing connection.")
    client_socket.close()


if __name__ == '__main__':
    client_program()
