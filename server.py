import json
import socket
import threading

HOST = "127.0.0.1"
PORT = 8080
FORMAT = "utf-8"
HEADER_SIZE = 64

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen()

clients = []
nicknames = []

keys = {}


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


def broadcast(message, type="message"):
    response = json.dumps(
        {
            "to": "all",
            "from": "server",
            "message": message,
            "type": type,
        }
    )
    for client in clients:
        send_message(client, response)


def handle_message(response):
    json_data = json.loads(response)
    reciever = json_data["to"]

    # print(json_data["message"])

    index = nicknames.index(reciever)
    client = clients[index]
    send_message(client, response)


def handle(client):
    while True:
        try:
            message = recieve_message(client)
            if message == "!quit":
                index = clients.index(client)
                clients.remove(client)
                client.close()
                nickname = nicknames[index]
                keys.pop(nickname)
                broadcast(f"{nickname} left the chat!")
                broadcast({"nickname": nickname, "key": ""}, type="delKey")
                nicknames.remove(nickname)
                break
            print(message)
            handle_message(message)
        except:
            index = clients.index(client)
            clients.remove(client)
            client.close()
            nickname = nicknames[index]
            keys.pop(nickname)
            broadcast(f"{nickname} left the chat!")
            broadcast({"nickname": nickname, "key": ""}, type="delKey")
            nicknames.remove(nickname)
            break


def recieve():
    while True:
        client, address = server.accept()
        print(f"Connected with {address}")

        send_message(client, json.dumps(keys))

        send_message(client, "NICK")
        nickname = recieve_message(client)
        while nickname in nicknames:
            send_message(client, "NICK")
            nickname = recieve_message(client)

        nicknames.append(nickname)
        clients.append(client)

        print(f"Nickname of the client is {nickname}")
        send_message(
            client,
            json.dumps(
                {
                    "to": nickname,
                    "from": "server",
                    "message": "Connected to the server!",
                }
            ),
        )
        key = recieve_message(client)
        keys[nickname] = key

        broadcast(f"{nickname} joined the chat!")
        broadcast({"nickname": nickname, "key": key}, type="addKey")

        thread = threading.Thread(target=handle, args=(client,))
        thread.start()


print(f"Server is listening on {HOST}:{PORT}...")
recieve()
