import socket
import sys


def main(argv: list[str] = []) -> None:
    port = 8000
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind(("127.0.0.1", port))
        server_socket.listen(5)

        conn, addr = server_socket.accept()
        with conn:
            print("Connected by", addr)
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                conn.sendall(data)


if __name__ == "__main__":
    argv = sys.argv
    main(argv)
