import socket
import rsa
from des1 import encryption, decryption

def request_public_key(client_socket):
    client_socket.send(b"REQUEST_PUBLIC_KEY")
    public_key_data = client_socket.recv(1024).decode()
    print(f"Public key received from server: {public_key_data}")
    return rsa.PublicKey.load_pkcs1(public_key_data.encode())

def client_program():
    host = socket.gethostname()
    port = 5000

    client_socket = socket.socket()
    client_socket.connect((host, port))

    print("1. Create Room")
    print("2. Join Room")
    choice = input("Enter your choice: ")

    if choice == "1":
        public_key = request_public_key(client_socket)

        # Generate DES key and send it to server
        des_key = "abcdefgh"
        encrypted_key = rsa.encrypt(des_key.encode(), public_key)
        client_socket.send(b"DES_KEY:" + encrypted_key)
        print("DES key sent to server.")

    while True:
        message = input(" -> ")
        if message.lower() == "exit":
            client_socket.close()
            break

        encrypted_message, _, _ = encryption(message, des_key)
        client_socket.send(encrypted_message.encode())

if __name__ == '__main__':
    client_program()
