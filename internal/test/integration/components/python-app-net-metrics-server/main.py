import socket

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    server_socket.bind(('', 8080))
    server_socket.listen(5)
    print("Server listening on :8080.")

    try:
        while True:
            conn, addr = server_socket.accept()
            with conn:
                data = conn.recv(1024).decode('utf-8')
                if data:
                    print(f"Received: {data.strip()}")
                    conn.sendall(b"ACK\n")
    except KeyboardInterrupt:
        print("\nServer shutting down.")
    finally:
        server_socket.close()

if __name__ == "__main__":
    main()
