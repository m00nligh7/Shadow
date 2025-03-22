import socket
import threading
import customtkinter
from PIL import Image, ImageTk
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import queue

ui_nickname = ""
loginwarning_counter = True
loginipportwarning_counter = True
private_key = None
server_public_key = None
aes_key = None
ip = None
port = None
selected_client = None
current_client_list = []
client_list_frame = None
hidden_emojiframe = True 

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
    global nick_entry, ip_entry, port_entry, client_socket, ui_nickname, loginwarning_counter, \
    txtwarning, aes_key, loginipportwarning_counter, ip, port
    nickname = str(nick_entry.get())
    ip = str(ip_entry.get())
    port = str(port_entry.get())
    if (ip == "" or port == "") and nickname == "":
        if loginipportwarning_counter == True and loginwarning_counter == True:
            txtwarningipport = customtkinter.CTkLabel(master=login, text="IP or Port were entered incorrectly", text_color="red")
            txtwarningipport.pack(fill=customtkinter.BOTH, padx=10, pady=(10, 10))
            loginipportwarning_counter = False
            txtwarning = customtkinter.CTkLabel(master=login, text="An empty nickname cannot be used", text_color="red")
            txtwarning.pack(fill=customtkinter.BOTH, padx=10, pady=(10, 10))
            loginwarning_counter = False
        else:
            print("Warning is already visible")
    elif ip == "" or port == "":
        if loginipportwarning_counter == True:
            txtwarningipport = customtkinter.CTkLabel(master=login, text="IP or Port were entered incorrectly", text_color="red")
            txtwarningipport.pack(fill=customtkinter.BOTH, padx=10, pady=(10, 10))
            loginipportwarning_counter = False
        else:
            print("Warning is already visible")
    elif (nickname == ""):
        if loginwarning_counter == True:
            txtwarning = customtkinter.CTkLabel(master=login, text="An empty nickname cannot be used", text_color="red")
            txtwarning.pack(fill=customtkinter.BOTH, padx=10, pady=(10, 10))
            loginwarning_counter = False
        else:
            print("Warning is already visible")
    else:
        ui_nickname = nickname
        try:
            port = int(port)
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((ip, port))
            private_key, public_key = generate_rsa_keys()
            server_public_key_bytes = client_socket.recv(1024)
            server_public_key = deserialize_public_key(server_public_key_bytes)
            client_socket.send(serialize_public_key(public_key))
            encrypted_aes_key = client_socket.recv(1024)
            aes_key = decrypt_rsa(encrypted_aes_key, private_key)
            encrypted_nickname = encrypt_aes(nickname, aes_key)
            print("ENcRYPTED_NIcK" + str(encrypted_nickname))
            client_socket.send(encrypted_nickname)
            main.deiconify()
            login.withdraw()
            client_hndlr_recv = threading.Thread(target=receive_msgs, args=(client_socket,), daemon=True)
            client_hndlr_recv.start()
            main.after(100, process_queue)
        except ValueError:
            print("ERROR: Port is not int")
        except socket.error as e:
            print("ERROR: cant connect")

def emoji_frame():
    global hidden_emojiframe
    if hidden_emojiframe == True:
        sidebar_frame_emoji.grid(row=0, column=3, sticky="ns", padx=5, pady=5)
        hidden_emojiframe = False
    else:
        sidebar_frame_emoji.grid_forget()
        hidden_emojiframe = True

def load_emojis():
    global sidebar_frame_emoji, chat_entry
    for widget in sidebar_frame_emoji.winfo_children():
        widget.destroy()

    emoji_categories = {
        "Smileys": ["😀", "😃", "😄", "😁", "😆", "😅",
                    "😂", "🤣", "😊", "😇", "🥰", "😍",
                    "🤩", "😘", "😗", "😚", "😙", "😋",
                    "😛", "😜", "🤪", "😝", "🤑", "🤗",
                    "🤭", "🤫", "🤔", "😐", "😑", "😶",
                    "😏", "😒", "🙄", "😬", "🤥", "😌",
                    "😔", "😪", "🤤", "😴", "😷", "🤒",
                    "🤕", "🤢", "🤮", "🤧", "🥵", "🥶",
                    "🥴", "😵", "🤯", "🤠", "🥳", "😎",
                    "🤓", "🧐", "😕", "😟", "🙁", "☹️",
                    "😮", "😯", "😲", "😳", "🥺", "😦",
                    "😧", "😨", "😰", "😥", "😢", "😭",
                    "😱", "😖", "😣", "😞", "😓", "😩",
                    "😫", "🥱", "😤", "😡", "😠", "🤬",
                    "😈", "👿", "💀", "☠️", "💩", "🤡",
                    "👹", "👺", "👻"],
        "Nature": ["🐶", "🐱", "🐭", "🐹", "🐰", "🦊",
                "🐻", "🐼", "🐨", "🐯", "🦁", "🐮",
                "🐷", "🐽", "🐸", "🐵", "🙈", "🙉",
                "🙊", "🐒", "🐔", "🐧", "🐦", "🐤",
                "🐣", "🐥", "🦆", "🦅", "🦉", "🦇",
                "🐺", "🐗", "🐴", "🦄", "🐝", "🐛",
                "🦋", "🐌", "🐞", "🐜", "🦟", "🦗",
                "🕷️", "🕸️", "🦂", "🐢", "🐍", "🦎",
                "🦖", "🦕", "🐙", "🦑", "🦐", "🦞",
                "🦀", "🐡", "🐠", "🐟", "🐬", "🐳",
                "🐋", "🦈", "🐊", "🐅", "🐆", "🦓",
                "🦍", "🦧", "🦣", "🐘", "🦛", "🦏",
                "🦒", "🦘", "🦬", "🐃", "🐂", "🐄",
                "🐎", "🐖", "🐑", "🦙", "🐐", "🦌",
                "🦔", "🐿️", "🦫", "🦡", "🦤", "🦥",
                "🦦", "🦨", "🦘", "🦡", "🐾"],
        "Food": ["🍏", "🍎", "🍐", "🍊", "🍋", "🍌",
                "🍉", "🍇", "🍓", "🫐", "🍈", "🍒",
                "🍑", "🥭", "🍍", "🥥", "🥝", "🍅",
                "🍆", "🥑", "🥦", "🥬", "🥒", "🌶️",
                "🫑", "🌽", "🥕", "🫒", "🧄", "🧅",
                "🥔", "🍠", "🥐", "🥯", "🍞", "🥖",
                "🥨", "🧀", "🥚", "🍳", "🧈", "🥞",
                "🧇", "🥓", "🥩", "🍗", "🍖", "🦴",
                "🌭", "🍔", "🍟", "🍕", "🫓", "🥪",
                "🥙", "🧆", "🌮", "🌯", "🫔", "🥗",
                "🥘", "🫕", "🥫", "🍝", "🍜", "🍲",
                "🍛", "🍣", "🍱", "🥟", "🦪", "🍤",
                "🍙", "🍚", "🍘", "🍥", "🥠", "🥮",
                "🍢", "🍡", "🍧", "🍨", "🍦", "🥧",
                "🧁", "🍰", "🎂", "🍮", "🍭", "🍬",
                "🍫", "🍿", "🍩", "🍪", "🌰", "🥜",
                "🍯", "🥛", "🍼", "🫖", "☕️", "🍵",
                "🧃", "🥤", "🍷", "🥃", "🍸", "🍹",
                "🧉", "🧊"],
        "Activities": ["⚽️", "🏀", "🏈", "⚾️", "🥎", "🎾",
                    "🏐", "🏉", "🥏", "🎱", "🪀", "🏓",
                    "🏸", "🏒", "🏑", "🥍", "🏏", "🪃",
                    "🥅", "⛳️", "🏹", "🎣", "🤿", "🥊",
                    "🥋", "🎽", "🛹", "🛼", "🛷", "⛸️",
                    "🥌", "🎿", "⛷️", "🏂", "🪂", "🏋️‍♀️",
                    "🏋️", "🏋️‍♂️", "🤼‍♀️", "🤼", "🤼‍♂️", "🤸‍♀️",
                    "🤸", "🤸‍♂️", "⛹️‍♀️", "⛹️", "⛹️‍♂️", "🤺",
                    "🤾‍♀️", "🤾", "🤾‍♂️", "🏌️‍♀️", "🏌️", "🏌️‍♂️",
                    "🏇", "🧘‍♀️", "🧘", "🧘‍♂️", "🏄‍♀️", "🏄",
                    "🏄‍♂️", "🏊‍♀️", "🏊", "🏊‍♂️", "🤽‍♀️", "🤽",
                    "🤽‍♂️", "🚣‍♀️", "🚣", "🚣‍♂️", "🧗‍♀️", "🧗",
                    "🧗‍♂️", "🚵‍♀️", "🚵", "🚵‍♂️", "🚴‍♀️", "🚴",
                    "🚴‍♂️", "🏆", "🥇", "🥈", "🥉", "🏅",
                    "🎖️", "🏵️", "🎗️", "🎫", "🎟️", "🎪",
                    "🤹‍♀️", "🤹", "🤹‍♂️", "🎭", "🩰", "🎨",
                    "🎬", "🎤", "🎧", "🎼", "🎹", "🥁",
                    "🪘", "🎷", "🎺", "🎸", "🪕", "🎻",
                    "🎲", "♟️", "🧩", "🎯", "🎳", "🎮"],
        "Travel": ["🚗", "🚕", "🚙", "🚌", "🚎", "🏎️",
                "🚓", "🚑", "🚒", "🚐", "🚚", "🚛",
                "🚜", "🦯", "🦽", "🦼", "🛴", "🚲",
                "🛵", "🏍️", "🛺", "🚨", "🚔", "🚍",
                "🚘", "🚖", "🚡", "🚠", "🚟", "🚃",
                "🚋", "🚞", "🚝", "🚄", "🚅", "🚈",
                "🚂", "🚆", "🚇", "🚊", "🚉", "✈️",
                "🛫", "🛬", "🛩️", "💺", "🛰️", "🚀",
                "🛸", "🚁", "🛶", "⛵️", "🚤", "🛥️",
                "🛳️", "⛴️", "🚢", "⚓️", "🛟", "🪝",
                "🚧", "🚦", "🚥", "🚏", "🗺️", "🗿",
                "🗽", "🗼", "🏰", "🏯", "🏟️", "🎡",
                "🎢", "🎠", "🏖️", "🏝️", "🏜️", "🌋",
                "🗻", "🏕️", "🛖", "🏠", "🏡", "🏘️",
                "🏚️", "🏗️", "🏭", "🏢", "🏬", "🏣",
                "🏤", "🏥", "🏦", "🏨", "🏪", "🏫",
                "🏩", "💒", "🏛️", "🗾", "🎑", "🏞️",
                "🌅", "🌄", "🌠", "🎇", "🎆", "🌇",
                "🌆", "🏙️", "🌃", "🌌", "🌉", "🌁"],
        "Objects": ["⌚️", "📱", "📲", "💻", "⌨️", "🖥️",
                "🖨️", "🖱️", "🖲️", "🕹️", "🗜️", "💽",
                "💾", "💿", "📀", "📼", "📷", "📸",
                "📹", "🎥", "📽️", "🎞️", "📞", "☎️",
                "📟", "📠", "📺", "📻", "🎙️", "🎚️",
                "🎛️", "🧭", "⏱️", "⏲️", "⏰", "🕰️",
                "⌛️", "⏳", "📡", "🔋", "🔌", "💡",
                "🔦", "🕯️", "🪔", "🧯", "🛢️", "💸",
                "💵", "💴", "💶", "💷", "💰", "💳",
                "🪙", "💎", "⚖️", "🪜", "🧰", "🪛",
                "🔧", "🔨", "⚒️", "🛠️", "⛏️", "🪚",
                "🔩", "⚙️", "🪤", "🧱", "⛓️", "🪝",
                "🧲", "🔫", "💣", "🧨", "🪓", "🔪",
                "🗡️", "⚔️", "🛡️", "🚬", "⚰️", "🪦",
                "⚱️", "🏺", "📿", "🧸", "💈", "🪪",
                "🏧", "🚮", "🚰", "♿️", "🚹", "🚺", "🚻", "🚼", "🚾",
                "🛂", "🛃", "🛄", "🛅", "🚸", "⚠️",
                "🚫", "🔞", "☢️", "☣️", "⬆️", "↗️",
                "➡️", "↘️", "⬇️", "↙️", "⬅️", "↖️",
                "↕️", "↔️", "↩️", "↪️", "⤴️", "⤵️",
                "🔃", "🔄", "🔙", "🔚", "🔛", "🔜",
                "🔝", "🔀", "🔁", "🔂", "▶️", "⏩",
                "⏭️", "⏯️", "◀️", "⏪", "⏮️", "🔼",
                "⏫", "🔽", "⏬", "⏸️", "⏹️", "⏺️",
                "🎦", "🔅", "🔆", "📶", "📳", "📴",
                "♀️", "♂️", "⚕️", "♾️", "✖️", "➕",
                "➖", "➗", "🟰", "♾️", "‼️", "⁉️",
                "❓", "❔", "❕", "❗️", "〰️", "💱",
                "💲", "⚕️", "♻️", "⚜️", "🔱", "📛",
                "🔰", "⭕️", "✅", "☑️", "✔️", "❌",
                "❎", "➰", "➿", "〽️", "✳️", "✴️",
                "❇️", "©️", "®️", "™️", "#️⃣", "*️⃣",
                "0️⃣", "1️⃣", "2️⃣", "3️⃣", "4️⃣", "5️⃣",
                "6️⃣", "7️⃣", "8️⃣", "9️⃣", "🔟", "🔠",
                "🔡", "🔢", "🔣", "🔤", "🅰️", "🆎",
                "🅱️", "🆑", "🆒", "🆓", "ℹ️", "🆔",
                "Ⓜ️", "🆕", "🆖", "🆗", "🆘", "🆙",
                "🆚", "🈁", "🈂️", "🈷️", "🈶", "🈯️",
                "🉐", "🈹", "🈚️", "🈲", "🉑", "🈸",
                "🈴", "🈳", "㊗️", "㊙️", "🈺", "🈵",
                "🔴", "🟠", "🟡", "🟢", "🔵", "🟣",
                "🟤", "⚫️", "⚪️", "🟥", "🟧", "🟨",
                "🟩", "🟦", "🟪", "🟫", "⬛️", "⬜️",
                "◼️", "◻️", "◾️", "◽️", "▪️", "▫️", "🔶",
                "🔷", "🔸", "🔹", "🔺", "🔻", "💠",
                "🔘", "🔳", "🔲"],
    }

    for category, emojis in emoji_categories.items():
        category_label = customtkinter.CTkLabel(sidebar_frame_emoji, text=category, font=("Arial", 12, "bold"))
        category_label.pack(fill = customtkinter.BOTH, padx = 5, pady = (10, 5))

        row = 1
        col = 0

        emoji_frame = customtkinter.CTkFrame(sidebar_frame_emoji, fg_color="transparent")
        emoji_frame.pack(fill=customtkinter.BOTH, padx=5, pady=5)

        for emoji in emojis:
            emoji_button = customtkinter.CTkButton(
                emoji_frame,
                text = emoji,
                font = ("Arial", 16),
                width = 30,
                height = 30,
                fg_color = "transparent",
                hover_color = "gray",
                command = lambda e=emoji: insert_emoji(e),
            )
            emoji_button.grid(row=row, column=col, padx=2, pady=2)

            col += 1
            if col >= 6:
                col = 0
                row += 1

        row += 1

def insert_emoji(emoji):
    global chat_entry
    chat_entry.insert("end", emoji)

def login_ui():
    global login, nick_entry, ip_entry, port_entry
    login = customtkinter.CTk()
    login.title("Login")
    login.geometry("300x300")
    login.resizable(False, False)
    ip_entry = customtkinter.CTkEntry(master=login, placeholder_text="Enter ip here")
    ip_entry.pack(fill=customtkinter.BOTH, padx=10, pady=(10, 5))
    port_entry = customtkinter.CTkEntry(master=login, placeholder_text="Enter port here")
    port_entry.pack(fill=customtkinter.BOTH, padx=10, pady=(10, 5))
    nick_entry = customtkinter.CTkEntry(master=login, placeholder_text="Enter your nickname")
    nick_entry.pack(fill=customtkinter.BOTH, padx=10, pady=(10, 5))
    nick_button = customtkinter.CTkButton(master=login, width=60, height=32, border_width=0, corner_radius=8, text="Join", command=get_nickname_ui)
    nick_button.pack(fill=customtkinter.BOTH, padx=10, pady=(5, 10))
    login.bind('<Return>', (lambda event: get_nickname_ui()))
    

def main_ui():
    global main, login, chat_entry, client_socket, txt, client_list_frame, sidebar_frame_emoji
    main = customtkinter.CTk()
    main.withdraw()
    #main.geometry("830x540")
    main.title("Shadow")
    main.resizable(False, False)
    sidebar_frame = customtkinter.CTkFrame(main, width=180, height=470)
    sidebar_frame.grid(row=0, column=0, sticky="ns", padx=5, pady=5)
    general_chat_button = customtkinter.CTkButton(sidebar_frame, text="General", command=lambda: select_client(None), width = 180)
    general_chat_button.pack(fill=customtkinter.BOTH, padx=5, pady=5)
    client_list_frame = customtkinter.CTkFrame(sidebar_frame, width=180, height=400, fg_color="transparent")
    client_list_frame.pack(fill=customtkinter.BOTH, padx=5, pady=5)
    sidebar_frame_emoji = customtkinter.CTkScrollableFrame(main, width=250, height=450)
    load_emojis()
    txt = customtkinter.CTkTextbox(main, width=600, height=470)
    txt.configure(state="disabled")
    txt.grid(row=0, column=1, columnspan=2, padx=5, pady=5)
    chat_entry = customtkinter.CTkEntry(main, width=550, height=30)
    chat_entry.grid(row=1, column=1, padx=5, pady=5)
    main.bind('<Return>', (lambda event: send_msgs(client_socket)))
    send_button = customtkinter.CTkButton(main, text="Send", command=lambda: send_msgs(client_socket), width=50, height=30)
    send_button.grid(row=1, column=2, padx=5, pady=5)
    bottom_left_frame = customtkinter.CTkFrame(main, width = 200, height = 50, fg_color="transparent")
    bottom_left_frame.grid(row = 1, column = 0, sticky = "sw", padx = 5, pady = 5)
    emojipng = Image.open("icons/emoji.png")
    emojipng = emojipng.resize((28, 28))
    icon_emoji = ImageTk.PhotoImage(emojipng)
    filepng = Image.open("icons/file.png")
    filepng = filepng.resize((28, 28))
    icon_file = ImageTk.PhotoImage(filepng)
    emoji_button = customtkinter.CTkButton(
        bottom_left_frame,
        image = icon_emoji,
        text = "",
        width = 28,
        height = 28,
        fg_color = "transparent",
        #hover_color = "gray",
        command = lambda: emoji_frame() 
    )
    emoji_button.grid(row = 0, column = 0, padx = 5, pady = 5)
    file_button = customtkinter.CTkButton(
        bottom_left_frame,
        image = icon_file,
        text = "",
        width = 28,
        height = 28,
        fg_color = "transparent",
        #hover_color = "gray",
        command = lambda: print("Button 2 is pressed")
    )
    file_button.grid(row = 0, column = 1, padx = 5, pady = 5)

def update_client_list(new_client_list):
    global client_list_frame, current_client_list
    if set(new_client_list) == set(current_client_list):
        return
    new_clients = set(new_client_list) - set(current_client_list)
    current_client_list = new_client_list
    for widget in client_list_frame.winfo_children():
        widget.destroy()
    for client in current_client_list:
        if client != ui_nickname:
            btn = customtkinter.CTkButton(client_list_frame, text=client, command=lambda c=client: select_client(c))
            btn.pack(fill=customtkinter.BOTH, padx=5, pady=5)
    if new_clients:
        print(f"New clients got connected: {', '.join(new_clients)}")
        

def select_client(client):
    global selected_client
    selected_client = client
    txt.configure(state="normal")
    if client:
        txt.insert("end", f"Chat with {client} selected\n")
    else:
        txt.insert("end", "General chat selected\n")
    txt.configure(state="disabled")

stop_threads = False

def receive_msgs(client_socket):
    global stop_threads
    while not stop_threads:
        try:
            encrypted_message = client_socket.recv(1024)
            if not encrypted_message:
                print("The server went down")
                message_queue.put("You got disconnected from the server\n")
                break

            message = decrypt_aes(encrypted_message, aes_key)
            if message.startswith("CLIENT_LIST:"):
                client_list = message.split(":")[1].split(",")
                update_client_list(client_list)
            elif message.startswith("PRIVATE:"):
                parts = message.split(":")
                if len(parts) >= 3:
                    sender = parts[1]
                    private_message = parts[2]
                    message_queue.put(f"Private from {sender}: {private_message}\n")
                else:
                    print(f"Incorrect private message: {message}")
            else:
                message_queue.put(f"{message}\n")
        except Exception as e:
            print(f"Error when trying to get a message: {e}")
            message_queue.put("Error when trying to get a message\n")
            break
    client_socket.close()

def on_closing():
    global stop_threads
    stop_threads = True
    main.quit()
    login.quit()
    print("APP IS DESTROYED")

def send_msgs(client_socket):
    global ui_nickname, message, chat_entry, txt, selected_client
    message = str(chat_entry.get())
    if message.strip():
        try:
            if selected_client:
                encrypted_message = encrypt_aes(f"PRIVATE:{selected_client}:{message}", aes_key)
                client_socket.send(encrypted_message)
                txt.configure(state="normal")
                txt.insert("end", f"{ui_nickname} (to {selected_client}): {message}\n")
                txt.configure(state="disabled")
            else:
                encrypted_message = encrypt_aes(f"{message}", aes_key)
                client_socket.send(encrypted_message)
                txt.configure(state="normal")
                txt.insert("end", f"{ui_nickname}: {message}\n")
                txt.configure(state="disabled")
            chat_entry.delete(0, "end")
        except Exception as e:
            print(f"Error when trying to send a message: {e}")
            client_socket.close()
            txt.configure(state="normal")
            txt.insert("end", "Error when trying to send a message\n")
            txt.configure(state="disabled")

def process_queue():
    if not main.winfo_exists():
        return
    while not message_queue.empty():
        message = message_queue.get()
        if txt.winfo_exists():
            txt.configure(state="normal")
            txt.insert("end", message)
            txt.configure(state="disabled")
    main.after(100, process_queue)

def on_closing():
    main.quit()
    login.quit()
    print("APP IS DESTROYED")

def main():
    global client_socket, private_key, server_public_key, aes_key
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    

    main_ui()
    login_ui()
    
    main.protocol("WM_DELETE_WINDOW", on_closing)
    login.protocol("WM_DELETE_WINDOW", on_closing)
    main.mainloop()

if __name__ == "__main__":
    main()
