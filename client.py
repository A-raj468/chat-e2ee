import socket
import sys


def main(argv):
    if len(argv) != 2:
        print(f"Usage: {argv[0]} <client port>")
        sys.exit(1)
    host = "127.0.0.1"
    server_port = 8000
    client_port = int(argv[1])

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.bind((host, client_port))
    client_socket.connect((host, server_port))
    data = client_socket.recv(1024)
    print(f"Received: {data.decode()}")

    data = b"Hello, server!"
    client_socket.sendall(data)

    client_socket.close()


if __name__ == "__main__":
    argv = sys.argv
    main(argv)
