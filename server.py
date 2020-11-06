import socket
from random import randint
from Crypto.Cipher import AES


def get_random_vector(n):
    string = "0123456789"
    vector = ""
    for i in range(n):
        vector += string[randint(0, 9)]
    return vector


K1 = b"0987654321098765"
K2 = b"0123456789123456"
K3 = b"1234567890123456"
IV_initial = b"0123456789012345"
IV1 = get_random_vector(16)
IV2 = get_random_vector(16)


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


def decrypt_cbc(cipher_list, key, vector):
    message_list = []
    result = ''
    for i in range(len(cipher_list)):
        if type(vector) == str:  # primul caz, in care vector este str
            vector = bytes(vector.encode("utf-8"))
        aes = AES.new(key, AES.MODE_CBC, vector)
        if i == 0:
            decrypted_message = aes.decrypt(cipher_list[i])
            decrypted_message = apply_xor(decrypted_message, vector)
            message_list.append(decrypted_message.decode("utf-8"))
            result += decrypted_message.decode('utf-8')
            xor_vector = cipher_list[i]
        else:
            decrypted_message = aes.decrypt(cipher_list[i])
            decrypted_message = apply_xor(decrypted_message, xor_vector)
            message_list.append(decrypted_message.decode("utf-8"))
            result += decrypted_message.decode('utf-8')
            xor_vector = cipher_list[i]
    print(result)
    return message_list


def decrypt_cfb(cipher_list, key, vector):
    message_list = []
    result = ''
    for i in range(len(cipher_list)):
        if type(vector) == str:  # primul caz, in care vector este str
            vector = bytes(vector.encode("utf-8"))
        aes = AES.new(key, AES.MODE_CFB, vector)
        if i == 0:
            decrypted_message = aes.encrypt(vector)
            decrypted_message = apply_xor(decrypted_message, cipher_list[i])
            message_list.append(decrypted_message.decode("utf-8"))
            result += str(decrypted_message.decode('utf-8'))
            cipher = cipher_list[i]
        else:
            decrypted_message = aes.encrypt(cipher)
            decrypted_message = apply_xor(decrypted_message, cipher_list[i])
            message_list.append(decrypted_message.decode("utf-8"))
            result += str(decrypted_message.decode('utf-8'))
            cipher = cipher_list[i]
    print(result)
    return message_list


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
        if len(codeblock_list) == 0:  #primul caz
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


server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('127.0.0.1', 12345))
server_socket.listen(5)

while True:
    print("Server waiting for a new connection...")
    client_socket_A, addr = server_socket.accept()
    client_socket_B, addr2 = server_socket.accept()
    print("Client connected from: ", addr)
    print("Client connected from: ", addr2)
    try:
        data = client_socket_A.recv(1024)
        if data.decode("utf-8") == "CBC":
            print("A va opera in modul CBC.")
            aes = AES.new(K3, AES.MODE_CBC, IV_initial)
            enc_K1 = aes.encrypt(K1)

            aes = AES.new(K3, AES.MODE_CBC, IV_initial)
            enc_IV1 = aes.encrypt(IV1.encode("utf-8"))

            client_socket_A.send(enc_K1)
            client_socket_A.send(enc_IV1)

            client_socket_B.send(bytes("CFB", "utf-8"))
            print(client_socket_B.recv(1024).decode("utf-8"))  # mesaj de confirmare de la B

            aes = AES.new(K3, AES.MODE_CBC, IV_initial)
            enc_K2 = aes.encrypt(K2)

            aes = AES.new(K3, AES.MODE_CBC, IV_initial)
            enc_IV2 = aes.encrypt(IV2.encode("utf-8"))

            client_socket_B.send(enc_K2)  # trimitem la B cheia si iv criptate
            client_socket_B.send(enc_IV2)

            data = client_socket_A.recv(1024)
            aes = AES.new(K1, AES.MODE_CBC, IV1.encode("utf-8"))
            data = aes.decrypt(data)
            print(data.decode("utf-8"))  # mesajul de confirmare criptat de la A

            data = client_socket_B.recv(1024)
            aes = AES.new(K2, AES.MODE_CBC, IV2.encode("utf-8"))
            data = aes.decrypt(data)
            print(data.decode("utf-8"))  # mesajul de confirmare criptat de la B

            codeblocks_number = client_socket_A.recv(1024)
            print("Numar de blocuri de criptotext primit: ", codeblocks_number.decode("utf-8"))
            codeblocks_list = []
            for c in range(int(codeblocks_number.decode("utf-8"))):
                data = client_socket_A.recv(16)
                codeblocks_list.append(data)
            print("Decriptat de la A:")
            decrypted_from_A = decrypt_cbc(codeblocks_list, K1, IV1)

            encrypted_for_B = ""
            for d in decrypted_from_A:  # il fac din lista string
                encrypted_for_B += d
            print("Criptam si trimitem catre B...")
            # urmeaza sa criptam ce am primit de la A si sa trimitem la B:
            encrypted_for_B = encrypt_plaintext_cfb(encrypted_for_B, K2, IV2)
            client_socket_B.send(bytes(str(len(encrypted_for_B)), "utf-8"))  # trimitem numarul de mesaje catre B
            for e in encrypted_for_B:
                client_socket_B.send(e)  # trimitem mesajele pe rand

            print(client_socket_B.recv(1024).decode("utf-8"))
            client_socket_A.send(bytes("KM: Criptarea s-a incheiat!", "utf-8"))

            client_socket_A.close()
            client_socket_B.close()

        elif data.decode("utf-8") == "CFB":
            print("A va opera in modul CFB.")
            aes = AES.new(K3, AES.MODE_CBC, IV_initial)
            enc_K1 = aes.encrypt(K1)

            aes = AES.new(K3, AES.MODE_CBC, IV_initial)
            enc_IV1 = aes.encrypt(IV1.encode("utf-8"))

            client_socket_A.send(enc_K1)
            client_socket_A.send(enc_IV1)

            client_socket_B.send(bytes("CBC", "utf-8"))
            print(client_socket_B.recv(1024).decode("utf-8"))  # mesaj de confirmare de la B

            aes = AES.new(K3, AES.MODE_CBC, IV_initial)
            enc_K2 = aes.encrypt(K2)

            aes = AES.new(K3, AES.MODE_CBC, IV_initial)
            enc_IV2 = aes.encrypt(IV2.encode("utf-8"))

            client_socket_B.send(enc_K2)  # trimitem la B cheia si iv criptate
            client_socket_B.send(enc_IV2)

            data = client_socket_A.recv(1024)
            aes = AES.new(K1, AES.MODE_CBC, IV1.encode("utf-8"))
            data = aes.decrypt(data)
            print(data.decode("utf-8"))  # mesajul de confirmare criptat de la A

            data = client_socket_B.recv(1024)
            aes = AES.new(K2, AES.MODE_CBC, IV2.encode("utf-8"))
            data = aes.decrypt(data)
            print(data.decode("utf-8"))  # mesajul de confirmare criptat de la B

            codeblocks_number = client_socket_A.recv(1024)
            print("Numar de blocuri criptotext primit: ", codeblocks_number.decode("utf-8"))
            codeblocks_list = []
            for c in range(int(codeblocks_number.decode("utf-8"))):
                data = client_socket_A.recv(16)
                codeblocks_list.append(data)

            print("Decriptat de la A:")
            decrypted_from_A = decrypt_cfb(codeblocks_list, K1, IV1)

            encrypted_for_B = ""
            for d in decrypted_from_A:  # il fac din lista string
                encrypted_for_B += d

            print("Criptam si trimitem catre B...")
            # urmeaza sa criptam ce am primit de la A si sa trimitem la B:
            encrypted_for_B = encrypt_plaintext_cbc(encrypted_for_B, K2, IV2)
            client_socket_B.send(bytes(str(len(encrypted_for_B)), "utf-8"))  # trimitem numarul de mesaje catre B
            for e in encrypted_for_B:
                client_socket_B.send(e)  # trimitem mesajele pe rand

            print(client_socket_B.recv(1024).decode("utf-8"))
            client_socket_A.send(bytes("KM: Criptarea s-a incheiat!", "utf-8"))

            client_socket_A.close()
            client_socket_B.close()
        else:
            exit("INCORRECT ENCRYPTION MODE, THE APPLICATION WILL CLOSE NOW.")
            client_socket_A.close()
            client_socket_B.close()
            server_socket.close()
    except Exception:
        print("Something went wrong. Try again!")

server_socket.close()
