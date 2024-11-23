import socket
import threading

# Dictionary untuk menyimpan public key (format: username -> (e, n))
public_keys = {}


def handle_request(client_socket):
    try:
        # Terima data dari client
        data = client_socket.recv(1024).decode()
        if data.startswith("STORE_KEY:"):
            # Simpan public key
            username, key = data[len("STORE_KEY:"):].split(":")
            e, n = map(int, key.split(","))
            public_keys[username] = (e, n)
            short_key = f"({e}, {str(n)[:6]}...)"
            print(f"Stored public key for {username}: {short_key}")
            client_socket.send(b"Key stored successfully.")
        elif data.startswith("REQUEST_KEY:"):
            # Kirim public key
            username = data[len("REQUEST_KEY:"):]
            if username in public_keys:
                key = public_keys[username]
                client_socket.send(f"{key[0]},{key[1]}".encode())
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

    while True:
        client_socket, _ = server_socket.accept()
        threading.Thread(target=handle_request, args=(client_socket,)).start()


if __name__ == '__main__':
    pka_program()
