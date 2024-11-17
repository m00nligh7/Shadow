import socket
import threading

clients = {}

def broadcast(message, client_socket):
    for client in clients:
        if client != client_socket:
            try:
                client.send(message)
            except:
                client.close()
                del clients[client]

def handle_client(client_socket):
    while True:
        try:
            nickname = client_socket.recv(1024).decode('utf-8')
            clients[client_socket] = nickname
            broadcast(f"{nickname} успешно присоединился к чату! Скажите {nickname} привет!".encode('utf-8'), client_socket)
            
            while True:
                message = client_socket.recv(1024)
                if not message:
                    break
                frmt_msg = f"{nickname}: {message.decode("utf-8")}".encode('utf-8')
                broadcast(frmt_msg, client_socket)
        except:
            pass
        finally:
            client_socket.close()
            if client_socket in clients:
                broadcast(f"{clients[client_socket]} покинул чат :()".encode('utf-8'))
                del clients[client_socket]

def main():
    global hostname
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('localhost', 8081))
    server_socket.listen(5)
    print("Server listening on localhost:8081")

    while True:
        client_socket, client_addr = server_socket.accept()
        print(f"Соединение со стороны - {client_addr}")
        client_hndlr = threading.Thread(target=handle_client, args=(client_socket,))
        client_hndlr.start()


if __name__ == "__main__":
    main()