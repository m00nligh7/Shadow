import socket
import threading

def receive_msgs(client_socket):
    while True:
        try:
            message = client_socket.recv(1024).decode('utf-8')
            print(f"\n{client_socket}: {message}")
        except:
            print("Отключено от сервера")
            client_socket.close()
            break

def send_msgs(client_socket):
    while True:
        message = input("<You>: ")
        client_socket.send(message.encode('utf-8'))

def main():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 8081))

    client_hndlr_recv = threading.Thread(target=receive_msgs, args=(client_socket,))
    client_hndlr_recv.start()
    client_hndlr_send = threading.Thread(target=send_msgs, args=(client_socket,))
    client_hndlr_send.start()


if __name__ == "__main__":
    main()