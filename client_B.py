import socket
from Crypto.Cipher import AES


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


client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('127.0.0.1', 12345))
K3 = b"1234567890123456"
IV_initial = "0123456789012345"

try:
    data = client_socket.recv(1024).decode("utf-8")
    if data == "CFB":
        print("Received from server(KM): ", data)
        client_socket.send(bytes("B: Voi opera in modul CFB.", "utf-8"))

        enc_K2 = client_socket.recv(1024)
        enc_IV2 = client_socket.recv(1024)

        aes = AES.new(K3, AES.MODE_CBC, IV_initial.encode("utf-8"))
        K2 = aes.decrypt(enc_K2)
        aes = AES.new(K3, AES.MODE_CBC, IV_initial.encode("utf-8"))
        IV2 = aes.decrypt(enc_IV2)

        confirm = "B: Putem incepe."
        aes = AES.new(K2, AES.MODE_CBC, IV2)
        confirm = aes.encrypt(bytes(confirm, "utf-8"))
        client_socket.send(confirm)

        data = client_socket.recv(1024).decode("utf-8")  # primim numarul de mesaje de la KM

        codeblocks_list = []
        for _ in range(int(data)):  # primim mesajele de la KM
            message = client_socket.recv(16)
            codeblocks_list.append(message)

        print("Mesajul decriptat(afisat ca string sau lista):")
        print(decrypt_cfb(codeblocks_list, K2, IV2))

        client_socket.send(bytes("B: Am decriptat!", "utf-8"))
    elif data == "CBC":
        print("Received from server(KM): ", data)

        client_socket.send(bytes("B: Voi opera in modul CBC.", "utf-8"))

        enc_K2 = client_socket.recv(1024)
        enc_IV2 = client_socket.recv(1024)

        aes = AES.new(K3, AES.MODE_CBC, IV_initial.encode("utf-8"))
        K2 = aes.decrypt(enc_K2)
        aes = AES.new(K3, AES.MODE_CBC, IV_initial.encode("utf-8"))
        IV2 = aes.decrypt(enc_IV2)

        confirm = "B: Putem incepe."
        aes = AES.new(K2, AES.MODE_CBC, IV2)
        confirm = aes.encrypt(bytes(confirm, "utf-8"))
        client_socket.send(confirm)

        data = client_socket.recv(1024).decode("utf-8")  # primim numarul de mesaje de la KM

        codeblocks_list = []
        for _ in range(int(data)):  # primim mesajele de la KM
            message = client_socket.recv(16)
            codeblocks_list.append(message)

        print("Mesajul decriptat(afisat ca string sau lista):")
        print(decrypt_cbc(codeblocks_list, K2, IV2))

        client_socket.send(bytes("B: Am decriptat!", "utf-8"))
except Exception:
    print("Something went wrong. Try again!")
client_socket.close()
