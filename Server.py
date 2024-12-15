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
    while crumbs_sent < total_crumbs:
        crumb = crumbs[crumbs_sent]
        print(f"[SERVER] Encrypting data with key for crumb {bin(crumb)}")
        encrypted_data = aes_encrypt(
            "When in the course of human events...", keys[crumb]
        )

        # Retry loop for acknowledgment
        while True:
            try:
                conn.send(encrypted_data)
                print("[SERVER] Encrypted data sent to client.")
                
                # Wait for acknowledgment
                ack = conn.recv(1024).decode()
                if ack == "ACK":
                    print("[SERVER] Client acknowledged packet.")
                    crumbs_sent += 1  # Move to the next crumb
                    break
                elif ack == "NACK":
                    print("[SERVER] Client rejected packet. Retrying...")
                elif '25':
                    print("[SERVER] Client acknowledged packet.")
                    print(f"[SERVER] Client acknowledged progress: {ack}%")
                    crumbs_sent += 1  # Move to the next crumb
                    break
                elif '50':
                    print("[SERVER] Client acknowledged packet.")
                    print(f"[SERVER] Client acknowledged progress: {ack}%")
                    crumbs_sent += 1  # Move to the next crumb
                    break
                elif '75':
                    print("[SERVER] Client acknowledged packet.")
                    print(f"[SERVER] Client acknowledged progress: {ack}%")
                    crumbs_sent += 1  # Move to the next crumb
                    break
                elif '100':
                    print(f"[SERVER] Client acknowledged progress: {ack}%")
                    break
                else:
                    print(f"[SERVER] Unexpected response from client: {ack}")
            except ConnectionResetError as e:
                print(f"[SERVER] Connection reset by client: {e}")
                conn.close()
                return

    print("[SERVER] All crumbs sent. Closing connection.")
    conn.close()
    print(f"[CONNECTION CLOSED] {addr}")

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

    handle_client()
