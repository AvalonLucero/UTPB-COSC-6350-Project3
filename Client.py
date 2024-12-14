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

        total_crumbs = 4  # Total number of crumbs expected
        decrypted_crumbs = 0

        try:
            while True:
                encrypted_data = client_socket.recv(1024)
                if not encrypted_data:
                    print("[CLIENT] No data received. Closing connection.")
                    break

                print("[CLIENT] Received encrypted data.")

                # Attempt to decrypt with each key
                decrypted = False
                decrypted_text = None
                for key_index in ['00', '01', '10', '11']:
                    key = keys[key_index]
                    try:
                        decrypted_data = aes_decrypt(encrypted_data, key)
                        if decrypted_data == "When in the course of human events...":  # Example match check
                            print(f"[CLIENT] Decryption successful with key {key_index}")
                            decrypted_crumbs += 1
                            decrypted = True
                            decrypted_text = decrypted_data
                            break
                    except Exception as e:
                        print(f"[CLIENT] Error during decryption with key {key_index}: {str(e)}")

                if decrypted:
                    # Write successfully decrypted data to the output file
                    with open(output_file, "a") as f:
                        f.write(f"Crumb {decrypted_crumbs}: {decrypted_text}\n")
                else:
                    print("[CLIENT] Failed to decrypt crumb with all keys.")

                # Calculate and display progress
                progress = (decrypted_crumbs / total_crumbs) * 100
                print(f"[CLIENT] Progress: {progress:.2f}% completed.")

                # Send ACK after receiving data (whether or not decryption was successful)
                try:
                    print("[CLIENT] Sending ACK to the server.")
                    client_socket.sendall("ACK".encode())  # Send acknowledgment to server
                except BrokenPipeError:
                    print("[CLIENT] Connection closed by server. Exiting...")
                    break

                # Send progress to the server
                try:
                    print(f"[CLIENT] Sending progress: {int(progress)}")
                    client_socket.sendall(str(int(progress)).encode())  # Send progress
                except BrokenPipeError:
                    print("[CLIENT] Connection closed by server. Exiting...")
                    break

        except KeyboardInterrupt:
            print("[CLIENT] Exiting gracefully.")
        finally:
            print(f"[CLIENT] Decryption completed. Results saved to {output_file}.")
            client_socket.close()


# Main function
if __name__ == "__main__":
    receive_crumbs()
