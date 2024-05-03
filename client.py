import json
import os
import socket
import threading

from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pss

Random.atfork()

SERVER = ("127.0.0.1", 8080)
FORMAT = "utf-8"
HEADER_SIZE = 64

nickname = input("Enter your nickname: ")

key = RSA.generate(2048)
private_key = key
serialized_key = key.publickey().exportKey().decode(FORMAT)

encrypt_keys = {}
sequence = {}

file_name = f"./keys/{nickname}/priv.pem"
if os.path.exists(file_name):
    with open(file_name, "rb") as f:
        signing_key = RSA.importKey(f.read().decode(FORMAT))
else:
    print(f"Not registered: {nickname}")
    exit(0)

lock = threading.Lock()
running = True

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(SERVER)

message = b"hello"
with open(f"./keys/{nickname}/pub.pem", "rb") as f:
    v = f.read().decode(FORMAT)
    verify_key = RSA.import_key(v)


def sign_message(message: bytes) -> str:
    h = SHA256.new(message)
    signer = pss.new(signing_key)
    return signer.sign(h).hex()


def verify_message(message: bytes, signature: str, sender: str) -> bool:
    h = SHA256.new(message)
    file_name = f"./keys/{sender}/pub.pem"
    if os.path.exists(file_name):
        with open(file_name, "rb") as f:
            verify_key = RSA.import_key(f.read().decode(FORMAT))
    else:
        print(f"Key for {sender} not found!")
        client.close()
        exit()
    verifier = pss.new(verify_key)
    try:
        verifier.verify(h, bytes.fromhex(signature))
    except (ValueError, TypeError):
        return False
    return True


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


response = recieve_message(client)
if response:
    response = json.loads(response)
    for key in response.keys():
        encrypt_keys[key] = RSA.import_key(response[key])
        sequence[key] = 0
    print(f"Players online: {', '.join(encrypt_keys.keys())}")
else:
    print("Disconnected from server!")
    client.close()
    running = False

response = recieve_message(client)
if response == "NICK":
    # nickname = input("Choose a nickname: "
    send_message(client, nickname)
    response = recieve_message(client)
if response == "NICK":
    print("Nickname already in use!")
    client.close()
    running = False
    exit()

if response:
    response = json.loads(response)
    print(f"{response['from']} to {response['to']}: {response['message']}")
else:
    print("Disconnected from server!")
    client.close()
    running = False

message = json.dumps(
    {
        "to": "server",
        "from": nickname,
        "key": serialized_key,
        "signature": sign_message(serialized_key.encode(FORMAT)),
    }
)
send_message(client, message)


def recieve():
    global running
    while running:
        try:
            response = recieve_message(client)
            if response:
                response = json.loads(response)
                if response["from"] == "server":
                    if response["type"] == "addKey":
                        message = json.loads(response["message"]["message"])
                        key = message["key"]
                        signature = message["signature"]
                        sender = message["from"]
                        verified = verify_message(key.encode(FORMAT), signature, sender)
                        if not verified:
                            print("Key verification failed!")
                            continue
                        encrypt_keys[sender] = RSA.import_key(key)
                        sequence[sender] = 0
                    elif response["type"] == "delKey":
                        encrypt_keys.pop(response["message"]["nickname"])
                        sequence.pop(response["message"]["nickname"])
                    elif response["type"] == "message":
                        print(
                            f"{response['from']} to {response['to']}: {response['message']}"
                        )
                else:
                    message = response["message"]
                    signature = response["signature"]
                    sender = response["from"]
                    seq = response["seq"]
                    verified = verify_message(message.encode(FORMAT), signature, sender)
                    if not verified:
                        print("Message verification failed!")
                        continue
                    if seq != sequence[sender]:
                        print(
                            "Sequence number verification failed! Message potentially dropped!"
                        )
                        continue
                    message = (
                        PKCS1_OAEP.new(private_key)
                        .decrypt(bytes.fromhex(message))
                        .decode(FORMAT)
                    )
                    print(f"{response['from']} to {response['to']}: {message}")
                    sequence[sender] += 1
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
    seq = 0
    while running:
        message = input()
        if message == "!quit":
            with lock:
                send_message(client, "!quit")
                client.close()
                running = False
                break
        receiver = input("To: ")
        if receiver not in encrypt_keys.keys():
            print(f"{receiver} is not online!")
            continue
        message = (
            PKCS1_OAEP.new(encrypt_keys[receiver]).encrypt(message.encode(FORMAT)).hex()
        )
        response = json.dumps(
            {
                "to": receiver,
                "from": nickname,
                "message": message,
                "signature": sign_message(message.encode(FORMAT)),
                "seq": seq,
            }
        )

        send_message(client, response)
        seq += 1


recieve_thread = threading.Thread(target=recieve)
recieve_thread.start()

write_thread = threading.Thread(target=write)
write_thread.start()

recieve_thread.join()
write_thread.join()
