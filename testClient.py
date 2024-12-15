import socket
import json
import random
import uuid
from Crypto import aes_decrypt, recompose_byte  # Assuming this is your custom AES decryption function

# Function to load keys from JSON file
def load_keys_from_json(file_path):
    with open(file_path, "r") as f:
        keys_hex = json.load(f)
    
    # Convert UUIDs to bytes
    keys = {k: uuid.UUID(v).bytes for k, v in keys_hex.items()}
    return keys

# Client function to receive and decrypt crumbs
def receive_crumbs():
    host = '127.0.0.1'
    port = 5555
    output_file = "decryption_results.txt"
    crumbs_data = []  # List to store decrypted crumbs

    # Prepare the output file
    with open(output_file, "w") as f:
        f.write("Decryption Results:\n")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((host, port))
        print("[CLIENT] Connected to server.")

        # Receive total crumbs count
        total_crumbs = int(client_socket.recv(1024).decode())
        print(f"[CLIENT] Total crumbs to receive: {total_crumbs}")
        received_crumbs = []

        # Track decryption status and keys
        decrypted_crumbs = [False] * total_crumbs  # Track decryption status for each crumb
        keys = load_keys_from_json("keys.json")
        remaining_keys = list(keys.keys())  # Initialize the pool of keys

        try:
            # Receive all crumbs
            for _ in range(total_crumbs):
                data = client_socket.recv(1024)
                if not data:
                    print("[CLIENT] No data received. Closing connection.")
                    break
                received_crumbs.append(data)

            # Acknowledge receipt of all crumbs
            print("[CLIENT] All crumbs received. Sending acknowledgment to server.")
            client_socket.sendall("ACK".encode("utf-8"))

            while not all(decrypted_crumbs):
                if not remaining_keys:
                    print("[CLIENT] No remaining keys to try. Exiting.")
                    break

                print(f"Remaining keys: {remaining_keys}")

                # Select a random key for this round
                selected_key_name = random.choice(remaining_keys)
                selected_key = keys[selected_key_name]
                print(f"[CLIENT] Using key {selected_key_name} for this round.")
                remaining_keys.remove(selected_key_name)

                print("[CLIENT] Starting decryption...")
                for i, encrypted_crumb in enumerate(received_crumbs):
                    try:
                        decrypted_text = aes_decrypt(encrypted_crumb, selected_key)
                        decrypted_crumbs[i] = True  # Mark the crumb as decrypted
                        crumbs_data.append(decrypted_text)  # Add the decrypted data to the list
                        print(f"[CLIENT] Crumb {i + 1} decrypted successfully.")
                        with open(output_file, "a") as f:
                            f.write(f"Crumb {i + 1}: {decrypted_text}\n")
                    except Exception as e:
                        # If decryption fails, record the failure
                        print(f"[CLIENT] Crumb {i + 1} failed to decrypt")

                # Calculate and display success/failure rates
                progress = (sum(decrypted_crumbs) / total_crumbs) * 100
                print(f"[CLIENT] Progress: {progress:.2f}% completed.")
                client_socket.sendall(f"PROGRESS:{progress:.2f}".encode("utf-8"))

        except KeyboardInterrupt:
            print("[CLIENT] Exiting gracefully.")
        finally:
            client_socket.close()

    return crumbs_data  # Return the decrypted crumbs for recomposition

# Function to reorder crumbs based on a text file
def reorder_crumbs(file_path, output_file_path):
    # Step 1: Read the decryption results from the file
    with open(file_path, "r") as file:
        lines = file.readlines()

    # Step 2: Extract the crumb number and its decryption result
    crumbs = []
    for line in lines:
        if line.startswith("Crumb"):
            # Example line: "Crumb 1: Decrypted data"
            parts = line.strip().split(":")
            crumb_number = int(parts[0].split()[1])  # Extract the crumb number
            decrypted_data = parts[1].strip() if len(parts) > 1 else ""  # Extract the decrypted data
            crumbs.append((crumb_number, decrypted_data))

    # Step 3: Sort the crumbs by crumb number
    crumbs.sort(key=lambda x: x[0])

    # Step 4: Write the sorted crumbs back to a new file
    with open(output_file_path, "w") as output_file:
        output_file.write("Decryption Results (Reordered):\n")
        for crumb in crumbs:
            output_file.write(f"Crumb {crumb[0]}: {crumb[1]}\n")

# Function to extract crumb numbers from the text file
def extract_crumb_numbers(file_path):
    crumb_numbers = []
    
    # Read the file
    with open(file_path, "r") as file:
        lines = file.readlines()

    # Loop through lines and extract the crumb numbers
    for line in lines:
        if line.startswith("Crumb"):
            # Extract crumb number (the number after "Crumb X:")
            parts = line.strip().split(":")
            crumb_number = int(parts[0].split()[1])  # Get the crumb number
            crumb_numbers.append(int(crumb_number))  # Convert to string and add to list

    return crumb_numbers

# Function to reassemble the message from crumbs
def reassemble_message(crumbs_data):
    # Prepare a list to store the recomposed bytes
    recomposed_bytes = []

    # Loop through the crumbs and recombine them into bytes
    for i in range(0, len(crumbs_data), 4):
        # Extract the 4 crumbs for the current byte
        crumb_set = crumbs_data[i:i+4]
        
        # Ensure crumb_set is a list of integers before passing it to recompose_byte
        if len(crumb_set) == 4:
            recomposed_byte = recompose_byte(crumb_set)
            recomposed_bytes.append(recomposed_byte)
        else:
            print(f"[ERROR] Incomplete crumb set: {crumb_set}")
            continue

    # Convert the byte array back to a string
    message = bytes(recomposed_bytes).decode('utf-8', errors='ignore')
    return message

# Main function
if __name__ == "__main__":
    input_file = "decryption_results.txt"
    output_file = "decryption_results_reordered.txt"

    # Step 1: Receive crumbs and get the decrypted data
    crumbs_data = receive_crumbs()

    # Step 2: Reorder crumbs and save to a new file
    reorder_crumbs(input_file, output_file)

    # Step 3: Extract the reordered crumb numbers
    crumbs = extract_crumb_numbers(output_file)

    reassembled_message = reassemble_message(crumbs)
    print(f"Reassembled message: {reassembled_message}")

    # Step 4: Recompose the final message from the crumb numbers and crumbs
