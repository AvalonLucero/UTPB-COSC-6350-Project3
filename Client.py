import socket
import json
from Crypto import aes_decrypt


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


# Client function
def receive_crumbs():
    host = '127.0.0.1'
    port = 5555

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((host, port))
        print("[CLIENT] Connected to server.")

        total_crumbs = 4  # Total number of crumbs expected
        decrypted_crumbs = 0

        try:
            while True:
                encrypted_data = client_socket.recv(1024)
                if not encrypted_data:
                    break

                print("[CLIENT] Received encrypted data.")

                # Attempt to decrypt with each key
                decrypted = False
                for key_index in ['00', '01', '10', '11']:
                    key = keys[key_index]
                    try:
                        decrypted_data = aes_decrypt(encrypted_data, key)
                        if decrypted_data == "When in the course of human events...":  # Example match check
                            print(f"[CLIENT] Decryption successful with key {key_index}")
                            decrypted_crumbs += 1
                            decrypted = True
                            break
                    except Exception as e:
                        print(f"[CLIENT] Error during decryption with key {key_index}: {str(e)}")

                if not decrypted:
                    print("[CLIENT] Failed to decrypt crumb with all keys.")

                # Calculate and display progress
                progress = (decrypted_crumbs / total_crumbs) * 100
                client_socket.sendall(str(int(progress)).encode())
                print(f"[CLIENT] Progress: {progress:.2f}% completed.")

                # Send progress to the server
                try:
                    client_socket.sendall(str(int(progress)).encode())
                except BrokenPipeError:
                    print("[CLIENT] Connection closed by server. Exiting...")
                    break

        except KeyboardInterrupt:
            print("[CLIENT] Exiting gracefully.")
        finally:
            client_socket.close()


# Main function
if __name__ == "__main__":
    receive_crumbs()
