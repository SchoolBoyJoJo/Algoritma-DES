import socket
from des1 import encryption, decryption  # import fungsi dari des1.py

def server_program():
    host = socket.gethostname()
    port = 5000  

    server_socket = socket.socket()  
    server_socket.bind((host, port))  
    server_socket.listen(2)
    conn, address = server_socket.accept()  
    print("Connection from: " + str(address))

    key = 'abcdefgh'  # Kunci DES harus 8 karakter
    while True:
        encrypted_data = conn.recv(1024).decode()  
        if not encrypted_data:
            break

        data = decryption(encrypted_data, key)  # Dekripsi pesan
        print("from connected user: " + str(data))

        response = input(' -> ')
        encrypted_response, _, _ = encryption(response, key)  # Enkripsi balasan
        conn.send(encrypted_response.encode())  

    conn.close()  

if __name__ == '__main__':
    server_program()
