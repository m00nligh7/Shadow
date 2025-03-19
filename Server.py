import socket
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import time

clients = {}

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(public_key_bytes):
    return serialization.load_pem_public_key(public_key_bytes)

def encrypt_aes(message, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
    return iv + encrypted_message

def decrypt_aes(encrypted_message, key):
    iv = encrypted_message[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_message[16:]) + decryptor.finalize()
    return decrypted_message.decode('utf-8')

def encrypt_rsa(data, public_key):
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_rsa(encrypted_data, private_key):
    return private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
def send_client_list():
    while True:
        try:
            client_list = [clients[client][0] for client in clients]
            for client in clients:
                encrypted_message = encrypt_aes(f"CLIENT_LIST:{','.join(client_list)}", clients[client][1])
                client.send(encrypted_message)
            time.sleep(5)
        except Exception as e:
            print(f"Error when trying to send a userlist: {e}")

def broadcast(message, client_socket):
    for client in list(clients.keys()):
        if client != client_socket:
            try:
                _, client_aes_key = clients[client]
                encrypted_message = encrypt_aes(message, client_aes_key)
                client.send(encrypted_message)
            except Exception as e:
                print(f"Error when trying to send a message to client: {e}")
                client.close()
                if client in clients:
                    del clients[client]

def handle_client(client_socket):
    private_key, public_key = generate_rsa_keys()
    try:
        client_socket.send(serialize_public_key(public_key))
        client_public_key_bytes = client_socket.recv(1024)
        client_public_key = deserialize_public_key(client_public_key_bytes)

        aes_key = os.urandom(32)
        encrypted_aes_key = encrypt_rsa(aes_key, client_public_key)
        client_socket.send(encrypted_aes_key)

        encrypted_nickname = client_socket.recv(1024)
        if not encrypted_nickname:
            raise Exception("Empty message with nickname")
        nickname = decrypt_aes(encrypted_nickname, aes_key)
        clients[client_socket] = (nickname, aes_key)

        broadcast(f"{nickname} has joined the chat!", client_socket)

        while True:
            try:
                encrypted_message = client_socket.recv(1024)
                if not encrypted_message:
                    break

                message = decrypt_aes(encrypted_message, aes_key)
                if message.startswith("PRIVATE:"):
                    parts = message.split(":")
                    if len(parts) >= 3:
                        recipient_nickname = parts[1]
                        private_message = parts[2]
                        for client in clients:
                            if clients[client][0] == recipient_nickname:
                                encrypted_response = encrypt_aes(f"PRIVATE:{nickname}:{private_message}", clients[client][1])
                                client.send(encrypted_response)
                                break
                else:
                    broadcast(f"{nickname}: {message}", client_socket)
            except Exception as e:
                print(f"Error when trying to get a message from client: {e}")
                break
    except Exception as e:
        print(f"Error processing client: {e}")
    finally:
        client_socket.close()
        if client_socket in clients:
            nickname, _ = clients[client_socket]
            broadcast(f"{nickname} left the chat :(", client_socket)
            del clients[client_socket]

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('localhost', 8081))
    server_socket.listen(5)
    print("Server listening on localhost:8081")
    threading.Thread(target=send_client_list, daemon=True).start()

    while True:
        client_socket, client_addr = server_socket.accept()
        print(f"Connection from - {client_addr}")
        client_hndlr = threading.Thread(target=handle_client, args=(client_socket,))
        client_hndlr.start()

if __name__ == "__main__":
    main()
