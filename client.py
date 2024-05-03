import json
import os
import socket
import threading

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import RSA
from Crypto.Random import atfork, get_random_bytes
from Crypto.Signature import pss
from Crypto.Util.Padding import pad, unpad

atfork()

SERVER = ("127.0.0.1", 8080)
FORMAT = "utf-8"
HEADER_SIZE = 64

nickname = input("Enter your nickname: ")

key = RSA.generate(2048)
private_key = key
serialized_key = key.publickey().exportKey().decode(FORMAT)

encrypt_keys = {}

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


def hmac_sign(message, reciever):
    hmac_key = encrypt_keys[reciever][1]
    hmac = HMAC.new(hmac_key, digestmod=SHA256)
    hmac.update(message)
    tag = hmac.digest()
    return tag.hex()


def hmac_verify(message, signature, sender):
    hmac_key = encrypt_keys[sender][1]
    hmac = HMAC.new(hmac_key, digestmod=SHA256)
    hmac.update(message)
    try:
        hmac.verify(bytes.fromhex(signature))
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
if response == "NICK":
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
                        keys = PBKDF2(
                            get_random_bytes(32).hex(),
                            get_random_bytes(32),
                            32 * 2,
                            count=100000,
                            hmac_hash_module=SHA256,
                        )
                        session_key, hmac_key = keys[:32], keys[32:]
                        encrypt_keys[sender] = (session_key, hmac_key)
                        keys = (session_key.hex(), hmac_key.hex())
                        keys = json.dumps(keys).encode(FORMAT)
                        keys = PKCS1_OAEP.new(RSA.import_key(key)).encrypt(keys).hex()
                        message = json.dumps(
                            {
                                "type": "skey",
                                "key": keys,
                                "signature": sign_message(keys.encode(FORMAT)),
                                "from": nickname,
                                "to": sender,
                            }
                        )
                        send_message(client, message)
                    elif response["type"] == "delKey":
                        encrypt_keys.pop(response["message"]["nickname"])
                    elif response["type"] == "message":
                        print(
                            f"{response['from']} to {response['to']}: {response['message']}"
                        )
                else:
                    msg_type = response["type"]
                    if msg_type == "message":
                        iv = bytes.fromhex(response["iv"])
                        message = response["message"]
                        signature = response["signature"]
                        sender = response["from"]
                        verified = hmac_verify(
                            message.encode(FORMAT), signature, sender
                        )
                        if not verified:
                            print("Message verification failed!")
                            continue
                        message = AES.new(
                            encrypt_keys[sender][0], AES.MODE_CBC, iv=iv
                        ).decrypt(bytes.fromhex(message))
                        message = unpad(message, AES.block_size).decode(FORMAT)
                        print(f"{response['from']} to {response['to']}: {message}")
                    elif msg_type == "skey":
                        key = response["key"]
                        signature = response["signature"]
                        sender = response["from"]
                        verified = verify_message(key.encode(FORMAT), signature, sender)
                        if not verified:
                            print("Key verification failed!")
                            continue
                        key = (
                            PKCS1_OAEP.new(private_key)
                            .decrypt(bytes.fromhex(key))
                            .decode(FORMAT)
                        )
                        keys = json.loads(key)
                        keys = bytes.fromhex(keys[0]), bytes.fromhex(keys[1])
                        encrypt_keys[sender] = keys
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
        if receiver not in encrypt_keys.keys():
            print(f"{receiver} is not online!")
            continue
        cipher = AES.new(encrypt_keys[receiver][0], AES.MODE_CBC)
        message = cipher.encrypt(pad(message.encode(FORMAT), AES.block_size)).hex()
        response = json.dumps(
            {
                "to": receiver,
                "from": nickname,
                "message": message,
                "signature": hmac_sign(message.encode(FORMAT), receiver),
                "type": "message",
                "iv": cipher.iv.hex(),
            }
        )

        send_message(client, response)


recieve_thread = threading.Thread(target=recieve)
recieve_thread.start()

write_thread = threading.Thread(target=write)
write_thread.start()

recieve_thread.join()
write_thread.join()
