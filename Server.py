import socket
import threading

clients = []

def broadcast(message, client_socket):
    for client in clients:
        if client != client_socket:
            try:
                client.send(message)
            except:
                client.close()
                clients.remove(client)

def handle_client(client_socket):
    while True:
        try:
            message = client_socket.recv(1024)
            if not message:
                break
            broadcast(message, client_socket)
        except:
            client_socket.close()
            clients.remove(client_socket)
            break

def main():
    global hostname
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('localhost', 8081))
    server_socket.listen(5)
    print("Server listening on localhost:8081")

    while True:
        client_socket, client_addr = server_socket.accept()
        hostname = client_addr
        clients.append(client_socket)
        print(f"Got connection from {client_addr} with nickname - ")
        client_hndlr = threading.Thread(target=handle_client, args=(client_socket,))
        client_hndlr.start()


if __name__ == "__main__":
    main()