import socket
import json
from Crypto import aes_encrypt

# Function to load keys from JSON file
def load_keys_from_json(file_path):
    with open(file_path, "r") as f:
        keys_hex = json.load(f)
    keys = {
        k: bytes.fromhex(v.replace("-", "")) for k, v in keys_hex.items()
    }
    return keys

# Load the keys from the JSON file
keys = load_keys_from_json("keys.json")

# Server function
def send_crumbs():
    crumbs = ['00', '01', '10', '11']  # Binary representation of crumb keys
    host = '127.0.0.1'
    port = 5555

    # Pre-encrypt the data for each key
    data_to_encrypt = "When in the course of human events..."
    encrypted_crumbs = {
        crumb: aes_encrypt(data_to_encrypt, keys[crumb]) for crumb in crumbs
    }

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen(1)
        print("[SERVER] Listening on port", port)

        conn, addr = server_socket.accept()
        with conn:
            print(f"[SERVER] Connected to {addr}")

            for crumb in crumbs:
                print(f"[SERVER] Sending encrypted data for crumb {crumb}")
                conn.send(encrypted_crumbs[crumb])  # Send pre-encrypted data
                print("[SERVER] Encrypted data sent to client.")

                # Wait for acknowledgment from client
                ack = conn.recv(1024).decode()
                if ack == "ACK":
                    print("[SERVER] Client acknowledged packet.")
                elif ack == "NACK":
                    print("[SERVER] Client rejected packet.")

            # After sending all crumbs, receive progress from client
            progress = conn.recv(1024).decode()
            print(f"[CLIENT PROGRESS] {progress}%")
            
            # Send back a final ACK or confirmation if needed
            conn.sendall("ACK".encode())

            conn.close()
            print(f"[SERVER] Connection closed")

if __name__ == "__main__":
    send_crumbs()
