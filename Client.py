import socket
import threading
import customtkinter

def receive_msgs(client_socket):
    while True:
        try:
            message = client_socket.recv(1024).decode('utf-8')
            print(f"{message}")
        except:
            print("Отключено от сервера")
            client_socket.close()
            break

def send_msgs(client_socket):
    while True:
        message = input("")
        client_socket.send(message.encode('utf-8'))
        

def get_nick_entry():
    global nick_entry, client_socket
    nick_entry_result = str(nick_entry.get())
    nickname = nick_entry_result
    client_socket.send(nickname.encode('utf-8'))

def main():
    global nick_entry, client_socket
    app = customtkinter.CTk()
    app.geometry("600x500")
    app.title("ShadowTalk")

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 8081))

    nick_entry = customtkinter.CTkEntry(master=app, placeholder_text="Введите ваш никнейм")
    nick_entry.pack(anchor=customtkinter.CENTER)
    nick_button = customtkinter.CTkButton(master=app, width=60, height=32, border_width=0, corner_radius=8, text="Войти", command=get_nick_entry)
    nick_button.place(anchor=customtkinter.W)

    client_hndlr_recv = threading.Thread(target=receive_msgs, args=(client_socket,))
    client_hndlr_recv.start()
    client_hndlr_send = threading.Thread(target=send_msgs, args=(client_socket,))
    client_hndlr_send.start()
    app.mainloop()

if __name__ == "__main__":
    main()