import socket
import threading

def server_thread(queue):
    host = '0.0.0.0'
    port = 12345

    while True:
        print(f"Listening on {host}:{port}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, port))
            s.listen()
            conn, addr = s.accept()
            with conn:
                print(f"Connected by {addr}")
                buffer = b''
                while True:
                    try:
                        data = conn.recv(4096)
                        if not data:
                            break
                        buffer += data
                        while b'\n' in buffer:
                            line, buffer = buffer.split(b'\n', 1)
                            queue.put(line)
                    except ConnectionResetError:
                        print("Connection reset by peer.")
                        break
                print("Client disconnected.")

def start_server(queue):
    thread = threading.Thread(target=server_thread, args=(queue,))
    thread.daemon = True
    thread.start()