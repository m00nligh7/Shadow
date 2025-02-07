import socket
import threading
import customtkinter

ui_nickname = ""
loginwarning_counter = True

def get_nickname_ui():
    global nick_entry, client_socket, ui_nickname, loginwarning_counter, txtwarning
    nickname = str(nick_entry.get())
    if nickname == "":
        if loginwarning_counter == True:
            txtwarning = customtkinter.CTkLabel(master=login, text="Пустой никнейм недопустим", text_color="red")
            txtwarning.pack(fill = customtkinter.BOTH, padx=10, pady=(10, 10))
            loginwarning_counter = False
        else:
            print("Warning is already visible")
    else:
        ui_nickname = nickname
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
    
    login.bind('<Return>', (lambda event: get_nickname_ui()))
    main.withdraw()

def main_ui():
    global main, login, chat_entry, client_socket, txt
    main = customtkinter.CTk()
    main.geometry("600x500")
    main.title("ShadowTalk")
    main.resizable(False, False)
    txt = customtkinter.CTkTextbox(main, width=600, height=470)
    txt.grid(row=0, column=1, columnspan=2)
    scrollbar = customtkinter.CTkScrollbar(txt, command=txt.yview)
    scrollbar.place(relheight=1, relx=0.974, rely=0)
    txt.configure(yscrollcommand=scrollbar.set)
    chat_entry = customtkinter.CTkEntry(main, width=550, height=30)
    chat_entry.grid(row=2, column=0, columnspan=2)
    main.bind('<Return>', (lambda event: send_msgs(client_socket)))
    send_button = customtkinter.CTkButton(main, text="Send", command=lambda: send_msgs(client_socket), width=50, height=30).grid(row=2, column=2, sticky="se")


def receive_msgs(client_socket):
    while True:
        try:
            message = client_socket.recv(1024).decode('utf-8')
            txt.insert("end", f"{message}\n")
            print(f"{message}")
        except:
            print("Отключено от сервера")
            txt.insert("end", "Отключено от сервера")
            client_socket.close()
            break

def send_msgs(client_socket):
    global ui_nickname, message, chat_entry, txt
    message = str(chat_entry.get())
    if message.strip():
        client_socket.send(message.encode('utf-8'))
        txt.insert("end", f"{ui_nickname}: {message}\n")
        chat_entry.delete(0, "end")

def on_closing():
    main.destroy()
    login.destroy()
    print("APP IS DESTROYED")

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
    main.protocol("WM_DELETE_WINDOW", on_closing)
    login.protocol("WM_DELETE_WINDOW", on_closing)
    main.mainloop()


if __name__ == "__main__":
    main()