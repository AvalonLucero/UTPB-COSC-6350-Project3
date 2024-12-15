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
    crumbs = [crumb for byte in file_data for crumb in decompose_byte(byte)]
    total_crumbs = len(crumbs)
    print(f"[SERVER] Total crumbs to send: {total_crumbs}")

    conn.send(str(total_crumbs).encode())  # Send total crumbs to client

    crumbs_sent = 0
    crumb_index = 1
    while crumbs_sent < total_crumbs:
        crumb = crumbs[crumbs_sent]
        print(f"[SERVER] Encrypting crumb {crumb} with key {bin(crumb)}")
        print(f"[SERVER] Crumb value: {crumb}, Index: {crumb_index}")
        encrypted_data = aes_encrypt(str(crumb), keys[crumb]) # Encrypt the crumb with its specific key
        crumbs_sent += 1
        crumb_index += 1
        conn.send(encrypted_data)

    while True:
        try:
            ack = conn.recv(1024).decode()
            if ack == "ACK":
                print(f"[SERVER] Client acknowledged crumbs recieved.")
                print("[SERVER] All crumbs sent successfully.")
            elif ack == "NACK":
                print(f"[SERVER] Client failed get crumbs.")
            elif ack.startswith("PROGRESS:"):
                # Extract and display the progress percentage
                progress = ack.split(":")[1]
                print(f"[SERVER] Client progress: {progress}%")
            else:
                print("[SERVER] Client closed connection.")
                break
        except ConnectionResetError as e:
            print(f"[SERVER] Connection reset: {e}")
            conn.close()
    conn.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a socket
    server.bind(("", PORT))  # Bind the server to the specified port
    server.listen(5)  # Listen for incoming connections (queue up to 5 clients)
    print(f"[LISTENING] Server is listening on port {PORT}")

    # Read file data to be sent to the client
    with open("data.txt", "rb") as f:  
        file_data = f.read()

    while True:  # Continuously accept new connections
        conn, addr = server.accept()  # Accept a new connection
        print(f"[NEW CONNECTION] {addr} connected.")

        # Start a new thread for handling the connected client
        thread = threading.Thread(target=handle_client, args=(conn, addr, file_data))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")

if __name__ == "__main__":
    start_server()
