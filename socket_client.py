import socket
from des1 import encryption, decryption 

def client_program():
    host = socket.gethostname()  
    port = 5000  

    client_socket = socket.socket()  
    client_socket.connect((host, port))  

    key = 'kolisane' 
    message = input(" -> ")  

    while message.lower().strip() != 'bye':
        encrypted_message, _, _ = encryption(message, key) 
        client_socket.send(encrypted_message.encode())  

        encrypted_data = client_socket.recv(1024).decode()  
        data = decryption(encrypted_data, key) 

        print('Received from server: ' + data)  

        message = input(" -> ")  

    client_socket.close()  

if __name__ == '__main__':
    client_program()
