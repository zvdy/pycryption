import socket
from threading import Thread
from asymetric import generate_asymmetric_keys, serialize_public_key, decrypt_with_private_key
from symetric import decrypt_message, encrypt_message

clients = []
symmetric_keys = {}

def handle_client(client_socket, client_address, private_key, public_key):
    try:
        public_key_bytes = serialize_public_key(public_key)
        client_socket.send(public_key_bytes)

        encrypted_symmetric_key = client_socket.recv(1024)
        symmetric_key = decrypt_with_private_key(private_key, encrypted_symmetric_key)
        symmetric_keys[client_socket] = symmetric_key

        while True:
            try:
                encrypted_message = client_socket.recv(1024)
                if not encrypted_message:
                    break
                message = decrypt_message(symmetric_key, encrypted_message).decode()
                print(f"Received from {client_address}: {message}")
                print("Server: ", end='', flush=True)
                broadcast_message(f"{client_address}: {message}", client_socket)
            except Exception as e:
                print(f"Error handling client {client_address}: {e}")
                break
    finally:
        clients.remove(client_socket)
        client_socket.close()

def broadcast_message(message, sender_socket=None):
    for client_socket in clients:
        if client_socket != sender_socket:
            symmetric_key = symmetric_keys.get(client_socket)
            if symmetric_key:
                encrypted_message = encrypt_message(symmetric_key, message.encode())
                client_socket.send(encrypted_message)

def handle_server_input():
    while True:
        message = input("Server: ")
        broadcast_message(f"Server: {message}")

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', 9999))
    server_socket.listen(5)
    print("Server listening on port 9999")

    private_key, public_key = generate_asymmetric_keys()

    input_thread = Thread(target=handle_server_input)
    input_thread.start()

    while True:
        client_socket, client_address = server_socket.accept()
        print(f"Accepted connection from {client_address}")
        clients.append(client_socket)
        client_handler = Thread(target=handle_client, args=(client_socket, client_address, private_key, public_key))
        client_handler.start()

if __name__ == "__main__":
    start_server()