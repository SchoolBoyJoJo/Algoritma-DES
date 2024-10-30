import socket
import threading
from des1 import encryption, decryption  # Import fungsi DES

# Fungsi untuk menerima pesan dari server
def receive_messages(client_socket, key):
    while True:
        try:
            # Terima pesan terenkripsi dari server
            encrypted_data = client_socket.recv(1024).decode()
            try:
                data = decryption(encrypted_data, key)  # Coba dekripsi pesan
                print(data)  # Tampilkan pesan jika berhasil didekripsi
            except:
                print("Received encrypted message (key mismatch)")  # Jika kunci berbeda
        except:
            print("An error occurred. Connection closed.")
            client_socket.close()
            break

def client_program():
    host = socket.gethostname()
    port = 5000

    client_socket = socket.socket()
    client_socket.connect((host, port))

    # Input nama dan kunci pengguna
    username = input("Enter your username: ")
    key = input("Enter your encryption key (8 characters): ")

    # Buat thread untuk menerima pesan dari server
    thread = threading.Thread(target=receive_messages, args=(client_socket, key))
    thread.start()

    # Kirim pesan ke server
    while True:
        message = input(" -> ")
        if message.lower().strip() == 'bye':
            break
        # Gabungkan nama pengguna dengan pesan
        full_message = f"[{username}]: {message}"
        encrypted_message, _, _ = encryption(full_message, key)
        client_socket.send(encrypted_message.encode())

    client_socket.close()

if __name__ == '__main__':
    client_program()
