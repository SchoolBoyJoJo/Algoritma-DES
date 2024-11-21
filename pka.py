import socket
import rsa

def generate_key_pair():
    # Membuat pasangan kunci (public dan private)
    public_key, private_key = rsa.newkeys(512)
    return public_key, private_key

def pka_server():
    host = '127.0.0.1'  # IP PKA
    port = 6000         # Port untuk komunikasi PKA

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)  # Maksimum 5 koneksi yang menunggu
    print("PKA server is running and listening for requests...")

    while True:
        client_socket, address = server_socket.accept()
        print(f"Connection from: {address}")

        # Generate pasangan kunci RSA baru
        public_key, private_key = generate_key_pair()
        print(f"Generated new public key for {address}")

        # Kirim public key ke server yang meminta
        client_socket.send(public_key.save_pkcs1().decode().encode())

        # Tutup koneksi setelah public key dikirim
        client_socket.close()

if __name__ == '__main__':
    pka_server()
