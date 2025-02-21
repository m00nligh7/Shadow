import socket
import threading
import customtkinter
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import queue

# Глобальные переменные
ui_nickname = ""
loginwarning_counter = True
private_key = None
server_public_key = None
aes_key = None

# Очередь для передачи сообщений между потоками
message_queue = queue.Queue()

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

def get_nickname_ui():
    global nick_entry, client_socket, ui_nickname, loginwarning_counter, txtwarning, aes_key
    nickname = str(nick_entry.get())
    if nickname == "":
        if loginwarning_counter == True:
            txtwarning = customtkinter.CTkLabel(master=login, text="Пустой никнейм недопустим", text_color="red")
            txtwarning.pack(fill=customtkinter.BOTH, padx=10, pady=(10, 10))
            loginwarning_counter = False
        else:
            print("Warning is already visible")
    else:
        ui_nickname = nickname
        encrypted_nickname = encrypt_aes(nickname, aes_key)
        print("ENcRYPTED_NIcK" + str(encrypted_nickname))
        client_socket.send(encrypted_nickname)
        main.deiconify()
        login.withdraw()

def login_ui():
    global login, nick_entry
    login = customtkinter.CTk()
    login.title("Login")
    login.geometry("250x200")
    login.resizable(False, False)
    nick_entry = customtkinter.CTkEntry(master=login, placeholder_text="Введите ваш никнейм")
    nick_entry.pack(fill=customtkinter.BOTH, padx=10, pady=(10, 5))
    nick_button = customtkinter.CTkButton(master=login, width=60, height=32, border_width=0, corner_radius=8, text="Войти", command=get_nickname_ui)
    nick_button.pack(fill=customtkinter.BOTH, padx=10, pady=(5, 10))
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
            encrypted_message = client_socket.recv(1024)
            print("ENcRYPTED_REcV" + str(encrypted_message))
            if not encrypted_message:
                print("Сервер отключился")
                message_queue.put("Отключено от сервера\n")
                break
            message = decrypt_aes(encrypted_message, aes_key)
            message_queue.put(f"{message}\n")
        except Exception as e:
            print(f"Ошибка при получении сообщения: {e}")
            message_queue.put("Ошибка при получении сообщения\n")
            break
    client_socket.close()

def send_msgs(client_socket):
    global ui_nickname, message, chat_entry, txt
    message = str(chat_entry.get())
    if message.strip():
        try:
            encrypted_message = encrypt_aes(f"{ui_nickname}: {message}", aes_key)
            print("ENcRYPTED_SEND" + str(encrypted_message))
            client_socket.send(encrypted_message)
            txt.insert("end", f"{ui_nickname}: {message}\n")
            chat_entry.delete(0, "end")
        except Exception as e:
            print(f"Ошибка при отправке сообщения: {e}")
            client_socket.close()
            txt.insert("end", "Ошибка при отправке сообщения\n")

def process_queue():
    while not message_queue.empty():
        message = message_queue.get()
        txt.insert("end", message)
    main.after(100, process_queue)  # Проверяем очередь каждые 100 мс

def on_closing():
    main.destroy()
    login.destroy()
    print("APP IS DESTROYED")

def main():
    global client_socket, private_key, server_public_key, aes_key
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 8081))

    private_key, public_key = generate_rsa_keys()
    server_public_key_bytes = client_socket.recv(1024)
    server_public_key = deserialize_public_key(server_public_key_bytes)
    client_socket.send(serialize_public_key(public_key))

    encrypted_aes_key = client_socket.recv(1024)
    aes_key = decrypt_rsa(encrypted_aes_key, private_key)

    main_ui()
    login_ui()
    client_hndlr_recv = threading.Thread(target=receive_msgs, args=(client_socket,), daemon=True)
    client_hndlr_recv.start()
    main.after(100, process_queue)  # Запускаем обработку очереди
    main.protocol("WM_DELETE_WINDOW", on_closing)
    login.protocol("WM_DELETE_WINDOW", on_closing)
    main.mainloop()

if __name__ == "__main__":
    main()