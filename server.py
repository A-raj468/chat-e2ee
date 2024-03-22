import socket
import sys


def main(argv: list[str] = []) -> None:
    port = 8000
    BUFFER_SIZE = 2048

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind(("127.0.0.1", port))
        server_socket.listen(2)

        print(f"Server started and listening on port {port}")

        clients = []

        for i in range(2):
            client_socket, addr = server_socket.accept()
            print(f"Connected by {addr}")
            client_socket.sendall(f"Hello, client {chr(65+i)}!".encode())
            encryption_key = client_socket.recv(BUFFER_SIZE)
            clients.append((addr, client_socket, encryption_key))

        for idx, (addr, client_socket, encryption_key) in enumerate(clients):
            client_socket.sendall(clients[1 - idx][2])

        while True:
            for idx, (addr, client_socket, encryption_key) in enumerate(clients):
                data = client_socket.recv(BUFFER_SIZE)
                if not data:
                    print(f"Disconnected by {addr}")
                    client_socket.close()
                    continue
                print(f"Data from {chr(65+idx)}: {data.hex()}")
                clients[1 - idx][1].sendall(data)


if __name__ == "__main__":
    argv = sys.argv
    main(argv)
