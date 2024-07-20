import socket

def listen_for_messages():
    host = '0.0.0.0'  # Listen on all interfaces, adjust if you want to listen on a specific one
    port = 5000  # The port should match the one used by the Comms VM to send messages
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print("ATC listening for alerts...")
        
        while True:
            conn, addr = s.accept()
            with conn:
                print(f"Connected by {addr}")
                message = conn.recv(1024).decode()
                print(f"Received alert: {message}")
                # Process the message or take appropriate action here

if __name__ == "__main__":
    listen_for_messages()

