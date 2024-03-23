import json
import socket
import threading

from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

Random.atfork()

SERVER = ("127.0.0.1", 8080)
FORMAT = "utf-8"
HEADER_SIZE = 64

key = RSA.generate(2048)
private_key = key
serialized_key = key.publickey().exportKey().decode(FORMAT)


def send_message(client, message):
    msg_length = str(len(message))
    msg_length = " " * (HEADER_SIZE - len(msg_length)) + msg_length
    client.send(msg_length.encode(FORMAT))
    client.send(message.encode(FORMAT))


def recieve_message(client):
    msg_length = client.recv(HEADER_SIZE).decode(FORMAT)
    if msg_length:
        msg_length = int(msg_length)
        msg = client.recv(msg_length).decode(FORMAT)
        return msg


lock = threading.Lock()
running = True

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(SERVER)
nickname = ""
keys = {}

response = recieve_message(client)
if response:
    response = json.loads(response)
    for key in response.keys():
        keys[key] = RSA.import_key(response[key])
    print(f"Nicknames in use: {keys.keys()}")
else:
    print("Disconnected from server!")
    client.close()
    running = False

response = recieve_message(client)
while response == "NICK":
    with lock:
        nickname = input("Choose a nickname: ")
    send_message(client, nickname)
    response = recieve_message(client)

if response:
    # print(response)
    response = json.loads(response)
    print(f"{response['from']} to {response['to']}: {response['message']}")
else:
    print("Disconnected from server!")
    client.close()
    running = False

send_message(client, serialized_key)


def recieve():
    global running
    while running:
        try:
            response = recieve_message(client)
            if response:
                response = json.loads(response)
                if response["from"] == "server":
                    if response["type"] == "addKey":
                        keys[response["message"]["nickname"]] = RSA.import_key(
                            response["message"]["key"]
                        )
                    elif response["type"] == "delKey":
                        keys.pop(response["message"]["nickname"])
                    elif response["type"] == "message":
                        print(
                            f"{response['from']} to {response['to']}: {response['message']}"
                        )
                else:
                    message = response["message"]
                    message = (
                        PKCS1_OAEP.new(private_key)
                        .decrypt(bytes.fromhex(message))
                        .decode(FORMAT)
                    )
                    print(f"{response['from']} to {response['to']}: {message}")
            else:
                print("Disconnected from server!")
                with lock:
                    client.close()
                    running = False
                break
        except Exception as e:
            print(f"An error occured! {e}")
            with lock:
                client.close()
                running = False
            break


def write():
    global running
    while running:
        message = input()
        if message == "!quit":
            with lock:
                send_message(client, "!quit")
                client.close()
                running = False
                break
        receiver = input("To: ")
        message = PKCS1_OAEP.new(keys[receiver]).encrypt(message.encode(FORMAT)).hex()
        response = json.dumps(
            {
                "to": receiver,
                "from": nickname,
                "message": message,
            }
        )

        send_message(client, response)


recieve_thread = threading.Thread(target=recieve)
recieve_thread.start()

write_thread = threading.Thread(target=write)
write_thread.start()

recieve_thread.join()
write_thread.join()
