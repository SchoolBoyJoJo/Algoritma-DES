import socket
import random
from rsa_code import generate_key_pair, encrypt_rsa, decrypt_rsa

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


def client_program():
    global public_key, private_key
    public_key, private_key = generate_key_pair()
    client_id = str(random.randint(1000, 9999))

    # Meminta public key PKA
    global pka_public_key
    pka_public_key = request_pka_public_key()
    if not pka_public_key:
        print("Failed to get PKA public key. Exiting.")
        return

    # Simpan public key client di PKA
    pka_socket = socket.socket()
    pka_socket.connect(("127.0.0.1", 6000))
    pka_socket.send(f"STORE_KEY:{client_id}:{public_key[0]},{public_key[1]}".encode())
    pka_socket.close()

    # Minta public key server dari PKA
    server_key = request_public_key_from_pka("server")
    if not server_key:
        print("Failed to get server key. Exiting.")
        return

    # Hubungkan ke server dan lakukan handshake
    client_socket = socket.socket()
    client_socket.connect((socket.gethostname(), 5000))

    if client_handshake(client_socket, server_key, client_id):
        print("Handshake successful!")
    else:
        print("Handshake failed.")
        client_socket.close()


if __name__ == '__main__':
    client_program()
