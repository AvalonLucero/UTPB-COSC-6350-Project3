import socket
import json
from Crypto import aes_decrypt, decompose_byte  # Import functions from your crypto file

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

# Function to handle receiving and decrypting crumbs
def receive_crumbs():
    decrypted_data = []
    total_crumbs = 100  # Assuming total number of crumbs is known
    attempted_keys = {index: [] for index in range(total_crumbs)}  # Track attempted keys for each crumb
    host = '127.0.0.1'

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((host, PORT))
        print("[CLIENT] Connected to server.")

        while len(decrypted_data) < total_crumbs:
            encrypted_crumb = client_socket.recv(1024)  # Adjust buffer size as needed
            if not encrypted_crumb:
                break

            print("[CLIENT] Received encrypted data.")
            current_index = len(decrypted_data)  # Simple index to determine current crumb
            possible_keys = [key for key in keys if key not in attempted_keys[current_index]]

            # Try to decrypt with available keys
            for key in possible_keys:
                try:
                    decrypted = aes_decrypt(encrypted_crumb, keys[key])
                    decrypted_data.append(decrypted)
                    attempted_keys[current_index].append(key)
                    print(f"[CLIENT] Decryption successful with key {bin(key)}")
                    break
                except ValueError:
                    print(f"[CLIENT] Decryption failed with key {bin(key)}")

            # Send progress back to the server after each round
            progress = (len(decrypted_data) / total_crumbs) * 100
            client_socket.sendall(str(int(progress)).encode())

            print(f"[CLIENT PROGRESS] {progress}% completed.")

        # Once decryption is complete, send a final acknowledgment
        client_socket.sendall("100".encode())  # 100% completed
        print("[CLIENT] Decryption complete. Connection closed.")

if __name__ == "__main__":
    receive_crumbs()
