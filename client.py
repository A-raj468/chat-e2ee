import socket
import sys


def main(argv):
    port = 8000
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.connect(("127.0.0.1", port))
        server_socket.sendall(b"Hello, world")
        data = server_socket.recv(1024)
        print(f"Received {data!r}")


if __name__ == "__main__":
    argv = sys.argv
    main(argv)
