import socket
import json
from Crypto import aes_decrypt  # Ensure this is correctly implemented

# Function to load keys from JSON file
def load_keys_from_json(file_path):
    with open(file_path, "r") as f:
        keys_hex = json.load(f)
    keys = {
        k: bytes.fromhex(v.replace("-", "")) for k, v in keys_hex.items()
    }
    return keys

# Load the keys from JSON file
keys = load_keys_from_json("keys.json")

# Client function
def receive_crumbs():
    host = '127.0.0.1'
    port = 5555
    output_file = "decrypted_crumbs.txt"

    # Prepare the output file
    with open(output_file, "w") as f:
        f.write("Decrypted Crumbs:\n")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((host, port))
        print("[CLIENT] Connected to server.")

        # Receive total crumbs count
        total_crumbs = int(client_socket.recv(1024).decode())
        print(f"[CLIENT] Total crumbs to decrypt: {total_crumbs}")
        decrypted_crumbs = 0

        try:
            while True:
                # Receive data (either encrypted binary data or a progress message)
                data = client_socket.recv(1024)
                if not data:
                    print("[CLIENT] No data received. Closing connection.")
                    break

                # Try decoding the data as a textual message
                try:
                    message = data.decode("utf-8")
                    if "REQUEST_ACK" in message:
                        # Handle progress acknowledgment requests
                        ack_progress = message.split(":")[1]
                        client_socket.sendall(f"ACK:{ack_progress}".encode("utf-8"))
                        print(f"[CLIENT] Acknowledged progress: {ack_progress}%")
                        continue
                except UnicodeDecodeError:
                    # If decoding fails, treat as binary (encrypted) data
                    print("[CLIENT] Received encrypted binary data.")
                    encrypted_data = data

                    decrypted = False
                    decrypted_text = None

                    # Attempt to decrypt using available keys
                    for key_index in ['00', '01', '10', '11']:
                        if key_index not in keys:
                            continue
                        key = keys[key_index]
                        try:
                            decrypted_text = aes_decrypt(encrypted_data, key)
                            if decrypted_text.strip() == "When in the course of human events...":
                                print(f"[CLIENT] Decryption successful with key {key_index}")
                                decrypted_crumbs += 1
                                decrypted = True
                                break
                        except Exception as e:
                            print(f"[CLIENT] Decryption failed with key {key_index}: {e}")

                    # Write successfully decrypted data to the output file
                    if decrypted:
                        with open(output_file, "a") as f:
                            f.write(f"Crumb {decrypted_crumbs}: {decrypted_text}\n")
                    else:
                        print("[CLIENT] Failed to decrypt data with all keys.")

                    # Calculate and display progress
                    progress = (decrypted_crumbs / total_crumbs) * 100
                    print(f"[CLIENT] Progress: {progress:.2f}% completed.")
                    if progress in {25.00, 50.00, 75.00}:
                        client_socket.sendall(str(progress).encode())
                    if progress in {100.00}:
                        client_socket.send(str(progress).encode())
                        break
                    # Send acknowledgment for the received crumb
                    client_socket.sendall("ACK".encode("utf-8"))

        except KeyboardInterrupt:
            print("[CLIENT] Exiting gracefully.")
        finally:
            if decrypted_crumbs == total_crumbs:
                print(f"[CLIENT] Decryption completed. Results saved to {output_file}.")
            client_socket.close()


# Main function
if __name__ == "__main__":
    receive_crumbs()