import socket
import threading
from des1 import encryption, decryption  # Import fungsi DES

# Variabel global untuk status koneksi
connected = True

def get_key_from_pka(pka_host, pka_port, client_id, pka_menu):
    pka_socket = socket.socket()
    pka_socket.connect((pka_host, pka_port))
    pka_socket.recv(1024)  # Terima pesan minta menu
    pka_socket.sendall(pka_menu.encode())
    pka_socket.recv(1024)  # Terima pesan minta id
    pka_socket.sendall(client_id.encode())
    key_message = pka_socket.recv(1024).decode()
    pka_socket.close()
    print(key_message)
    return key_message.split(": ")[-1].strip()  # Ambil key dari pesan

# Fungsi untuk menerima pesan dari server
def receive_messages(client_socket, key):
    global connected
    while connected:
        try:
            # Terima pesan terenkripsi dari server
            encrypted_data = client_socket.recv(1024).decode()
            if not encrypted_data:
                break

            try:
                data = decryption(encrypted_data, key)  # Coba dekripsi pesan
                print(data)  # Tampilkan pesan jika berhasil didekripsi
            except:
                print("Received encrypted message (key mismatch)")  # Jika kunci berbeda
        except:
            if connected:  # Hanya tampilkan error jika masih terhubung
                print("An error occurred. Connection closed.")
            break
    client_socket.close()

def client_program():
    global connected
    host = socket.gethostname()
    port = 5000
    pka_host = socket.gethostname()
    pka_port = 5555
    
    username = input("Enter your username: ")
    client_id = input("Enter your 6-digit ID: ")
    key = get_key_from_pka(pka_host, pka_port, client_id, '1')
    
    client_socket = socket.socket()
    client_socket.connect((host, port))
    
    # Pilih Client yang ingin dihubungi
    while True:
        connect_to = input("Enter the 6-Digit ID of user you want to chat with: ")
        target_key = get_key_from_pka(pka_host, pka_port, connect_to, '2')
        if target_key == True:
            break
        else: print("ID is not matching any client")

    # Buat thread untuk menerima pesan dari server
    thread = threading.Thread(target=receive_messages, args=(client_socket, key))
    thread.start()

    # Kirim pesan ke server
    while True:
        message = input(" -> ")
        if message.lower().strip() == 'exit':
            connected = False  # Set status koneksi menjadi False
            print("Exiting chat room...")
            client_socket.close()  # Tutup koneksi ke server
            break

        # Gabungkan nama pengguna dengan pesan
        full_message = f"[{username}]: {message}"
        encrypted_message_with_own_key, _, _ = encryption(full_message, key)
        encrypted_message_with_target_key, _, _ = encryption(encrypted_message_with_own_key, target_key)
        client_socket.send(encrypted_message_with_target_key.encode())

if __name__ == '__main__':
    client_program()
