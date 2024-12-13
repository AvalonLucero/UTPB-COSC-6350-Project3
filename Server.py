import socket
import threading
import json
from Crypto import aes_encrypt, decompose_byte  # Import functions from your crypto file

# Load keys from keys.json
def load_keys_from_json(file_path):
    with open(file_path, "r") as f:
        keys_hex = json.load(f)
    # Convert keys from hex string to bytes
    keys = {
        int(k, 2): bytes.fromhex(v.replace("-", "")) for k, v in keys_hex.items()
    }
    return keys

keys = load_keys_from_json("keys.json")

PORT = 5555


def handle_client(conn, addr, file_data):
    print(f"[NEW CONNECTION] {addr} connected.")
    crumbs = [crumb for byte in file_data for crumb in decompose_byte(byte)]
    print(f"[INFO] File data decomposed into crumbs: {crumbs}")

    while True:
        for crumb in crumbs:
            print(f"[SERVER] Encrypting data with key for crumb {bin(crumb)}")
            encrypted_data = aes_encrypt(
                "The quick brown fox jumps over the lazy dog.", keys[crumb]
            )
            conn.send(encrypted_data)
            print("[SERVER] Encrypted data sent to client.")

            ack = conn.recv(1024).decode()
            if ack == "ACK":
                print("[SERVER] Client acknowledged packet.")
                continue
            elif ack == "NACK":
                print("[SERVER] Client rejected packet.")

        # Receive progress updates from the client
        progress = conn.recv(1024).decode()
        print(f"[CLIENT PROGRESS] {progress}%")
        if progress == "100":
            print("[SERVER] Client completed decoding. Closing connection.")
            break

    conn.close()
    print(f"[CONNECTION CLOSED] {addr}")


def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("", PORT))
    server.listen(5)
    print(f"[LISTENING] Server is listening on port {PORT}")

    with open("risk.bmp", "rb") as f:
        file_data = f.read()

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr, file_data))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")


if __name__ == "__main__":
    start_server()
