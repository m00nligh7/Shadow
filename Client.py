import socket
import threading
import customtkinter

def get_nickname_ui():
    global nick_entry, client_socket
    nickname = str(nick_entry.get())
    client_socket.send(nickname.encode('utf-8'))
    main.deiconify()
    login.withdraw()

def login_ui():
    global login, nick_entry
    login = customtkinter.CTk()
    login.title("Login")
    login.geometry("250x200")
    login.resizable(False, False)
    nick_entry = customtkinter.CTkEntry(master=login, placeholder_text="Введите ваш никнейм", )
    nick_entry.pack(fill = customtkinter.BOTH, padx=10, pady=(10, 5))
    nick_button = customtkinter.CTkButton(master=login, width=60, height=32, border_width=0, corner_radius=8, text="Войти", command=get_nickname_ui)
    nick_button.pack(fill = customtkinter.BOTH, padx=10, pady=(5, 10))
    main.withdraw()

def main_ui():
    global main, login
    main = customtkinter.CTk()
    main.geometry("600x500")
    main.title("ShadowTalk")
    

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

def main():
    global client_socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 8081))
    main_ui()
    login_ui()
    client_hndlr_recv = threading.Thread(target=receive_msgs, args=(client_socket,))
    client_hndlr_recv.start()
    client_hndlr_send = threading.Thread(target=send_msgs, args=(client_socket,))
    client_hndlr_send.start()
    main.mainloop()


if __name__ == "__main__":
    main()