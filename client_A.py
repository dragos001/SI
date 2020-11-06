import socket
from Crypto.Cipher import AES

IV_initial = "0123456789012345"
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('127.0.0.1', 12345))
K3 = b"1234567890123456"


def add_padding(array):
    start = len(array)
    for _ in range(start, 16):
        array += '0'
    return array


def apply_xor(string1, string2):
    result = bytearray()
    if type(string1) == str:
        string1 = bytes(string1, "utf-8")
    if type(string2) == str:
        string2 = bytes(string2, "utf-8")
    for s1, s2 in zip(string1, string2):
        result.append(s1 ^ s2)
    return result


def encrypt_plaintext_cbc(plaintext, key, vector):
    codeblock_list = []
    ok = 1
    i = 0
    j = 16
    if len(plaintext) < 16:  # in cazul in care mesajul are mai putin de 16bytes
        j = len(plaintext)
    while ok == 1:
        if j == len(plaintext):  # cand s-a ajuns la ultimul bloc
            ok = 0
        message_block = ""
        for k in range(i, j):
            message_block += plaintext[k]
        if len(message_block) < 16:
            message_block = add_padding(message_block)
        if type(vector) == str:  # primul caz, in care vector este str
            vector = bytes(vector.encode("utf-8"))
        aes = AES.new(key, AES.MODE_CBC, vector)
        if len(codeblock_list) == 0:  # primul caz
            cipher = apply_xor(message_block, vector)
            enc_message = aes.encrypt(cipher)
            codeblock_list.append(enc_message)
            cipher = enc_message
        else:
            cipher = apply_xor(message_block, cipher)  # vector e str/bytearray, transform message_block la str
            enc_message = aes.encrypt(cipher)
            codeblock_list.append(enc_message)
            cipher = enc_message
        i = j
        j = j + 16
        if j > len(plaintext):
            j = len(plaintext)  # pentru ultimul bloc de mesaj
    return codeblock_list


def encrypt_plaintext_cfb(plaintext, key, vector):
    codeblock_list = []
    ok = 1
    i = 0
    j = 16
    if len(plaintext) < 16:  # in cazul in care mesajul are mai putin de 16bytes
        j = len(plaintext)
    while ok == 1:
        if j == len(plaintext):  # cand s-a ajuns la ultimul bloc
            ok = 0
        message_block = ""
        for k in range(i, j):
            message_block += plaintext[k]
        if len(message_block) < 16:
            message_block = add_padding(message_block)
        if type(vector) == str:  # primul caz, in care vector este str
            vector = bytes(vector.encode("utf-8"))
        aes = AES.new(key, AES.MODE_CFB, vector)
        if len(codeblock_list) == 0:
            enc_message = aes.encrypt(vector)
            enc_message = apply_xor(enc_message, message_block)
            codeblock_list.append(enc_message)
            xor_vector = enc_message
        else:
            enc_message = aes.encrypt(xor_vector)
            enc_message = apply_xor(enc_message, message_block)
            codeblock_list.append(enc_message)
            xor_vector = enc_message
        i = j
        j = j + 16
        if j > len(plaintext):
            j = len(plaintext)  # pentru ultimul bloc de mesaj
    return codeblock_list


try:
    message = input("SEND ENCRYPTION MODE: ")
    client_socket.send(bytes(message, "utf-8"))

    if message == "CBC":
        enc_K1 = client_socket.recv(1024)
        enc_IV1 = client_socket.recv(1024)

        aes = AES.new(K3, AES.MODE_CBC, IV_initial.encode("utf-8"))
        K1 = aes.decrypt(enc_K1)

        aes = AES.new(K3, AES.MODE_CBC, IV_initial.encode("utf-8"))
        IV1 = aes.decrypt(enc_IV1)

        confirm = "A: Putem incepe."
        aes = AES.new(K1, AES.MODE_CBC, IV1)
        confirm = aes.encrypt(bytes(confirm, "utf-8"))
        client_socket.send(confirm)

        f = open("fisier.txt", "r")
        f = f.read()
        print("Mesajul de criptat: ", f)

        message = encrypt_plaintext_cbc(f, K1, IV1)
        client_socket.send(bytes(str(len(message)), "utf-8"))
        for m in message:
            client_socket.send(bytes(m))

        print(client_socket.recv(1024).decode("utf-8"))

    elif message == "CFB":
        enc_K1 = client_socket.recv(1024)
        enc_IV1 = client_socket.recv(1024)

        aes = AES.new(K3, AES.MODE_CBC, IV_initial.encode("utf-8"))
        K1 = aes.decrypt(enc_K1)

        aes = AES.new(K3, AES.MODE_CBC, IV_initial.encode("utf-8"))
        IV1 = aes.decrypt(enc_IV1)

        confirm = "A: Putem incepe."
        aes = AES.new(K1, AES.MODE_CBC, IV1)
        confirm = aes.encrypt(bytes(confirm, "utf-8"))
        client_socket.send(confirm)

        f = open("fisier.txt", "r")
        f = f.read()
        print("Mesajul de criptat: ", f)

        message = encrypt_plaintext_cfb(f, K1, IV1)
        client_socket.send(bytes(str(len(message)), "utf-8"))
        for m in message:
            client_socket.send(bytes(m))

        print(client_socket.recv(1024).decode("utf-8"))

    # data = client_socket.recv(1024).decode("utf-8")
    # print("Received from server:", data)
    # message = input("Send a character to the server:")
    # client_socket.send(bytes(message, "utf-8"))
except Exception:
    print("Something went wrong. Try again!")
client_socket.close()
