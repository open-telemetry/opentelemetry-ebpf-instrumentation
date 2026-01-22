import socket
import time
import os

def main():
    counter = 1
    address_raw = os.getenv("TARGET_ADDRESS", "localhost:8080")
    host, port = address_raw.split(":")
    port = int(port)

    while True:
        print(f"[{counter}] Connecting to {host}:{port}...")
        
        try:
            with socket.create_connection((host, port), timeout=2) as conn:
                message = f"Hello World {counter}\n"
                conn.sendall(message.encode('utf-8'))

                response = conn.recv(1024).decode('utf-8')
                print(f"Server says: {response.strip()}")
                
            print("Connection closed. Sleeping 3s...")
        except Exception as e:
            print(f"Connection failed: {e}")

        counter += 1
        time.sleep(3)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nClient stopped")
