import socket
import sys


def main(argv: list[str] = []) -> None:
    port = 8000
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind(("127.0.0.1", port))
        server_socket.listen(2)

        print(f"Server started and listening on port {port}")

        clients = {}

        while True:
            while len(clients) < 2:
                client_socket, addr = server_socket.accept()
                print(f"Connected by {addr}")
                clients[addr] = client_socket

            for idx, (addr, client_socket) in enumerate(clients.items()):
                client_socket.sendall(f"Hello, client {chr(65+idx)}!".encode())
                data = client_socket.recv(1024)
                if not data:
                    print(f"Disconnected by {addr}")
                    clients[addr].close()
                    continue
                print(f"Received: {data.decode()}")

            break


if __name__ == "__main__":
    argv = sys.argv
    main(argv)
