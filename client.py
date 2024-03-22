import socket
import sys

from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

Random.atfork()


def main(argv):
    if len(argv) != 2:
        print(f"Usage: {argv[0]} <client port>")
        sys.exit(1)
    host = "127.0.0.1"
    server_port = 8000
    client_port = int(argv[1])

    BUFFER_SIZE = 2048

    key = RSA.generate(1024)
    public_key = key.publickey().export_key()
    private_key = key

    decryptor = PKCS1_OAEP.new(private_key)

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.bind((host, client_port))
    client_socket.connect((host, server_port))
    data = client_socket.recv(BUFFER_SIZE)
    print(f"Received: {data.decode()}")
    # print(f"Sending: {public_key.hex()}")
    client_socket.sendall(public_key)
    data = client_socket.recv(BUFFER_SIZE)
    # print(f"Key: {data.hex()}")
    encryption_key = RSA.import_key(data)
    encryptor = PKCS1_OAEP.new(encryption_key)

    print("Enter 'exit' to exit")

    while True:
        data = input("> ").encode()
        if data == b"exit":
            break

        data = encryptor.encrypt(data)
        # print(f"Sending: {data.hex()}")
        client_socket.sendall(data)
        data = client_socket.recv(BUFFER_SIZE)
        data = decryptor.decrypt(data)
        print(f"Received: {data.decode()}")

    client_socket.close()


if __name__ == "__main__":
    argv = sys.argv
    main(argv)
