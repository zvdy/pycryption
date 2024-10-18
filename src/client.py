import socket
from threading import Thread
from asymetric import deserialize_public_key, encrypt_with_public_key
from symetric import generate_symmetric_key, encrypt_message, decrypt_message

def receive_messages(client_socket, symmetric_key):
    while True:
        try:
            encrypted_message = client_socket.recv(1024)
            if not encrypted_message:
                break
            message = decrypt_message(symmetric_key, encrypted_message).decode()
            if message.startswith("Server:"):
                print(f"Received: {message}")
                print("Server")
            else:
                print(f"Received from {client_socket.getpeername()}: {message}")
            print("Enter message: ", end='', flush=True)
        except Exception as e:
            print(f"Error receiving message: {e}")
            client_socket.close()
            break

def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 9999))

    public_key_bytes = client_socket.recv(1024)
    public_key = deserialize_public_key(public_key_bytes)

    symmetric_key = generate_symmetric_key()
    encrypted_symmetric_key = encrypt_with_public_key(public_key, symmetric_key)
    client_socket.send(encrypted_symmetric_key)

    receive_thread = Thread(target=receive_messages, args=(client_socket, symmetric_key))
    receive_thread.start()

    while True:
        try:
            message = input("Enter message: ").encode()
            encrypted_message = encrypt_message(symmetric_key, message)
            client_socket.send(encrypted_message)
        except BrokenPipeError:
            print("Connection lost. Exiting.")
            break
        except Exception as e:
            print(f"Error sending message: {e}")
            break

if __name__ == "__main__":
    start_client()