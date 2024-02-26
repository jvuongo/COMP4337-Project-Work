import socket
import threading
from base64 import b64decode
from bloom import *
from helper import HEADER_SIZE, receive_message, send_match_result

# PORT DEFS
PORT = 55000
SERVER = "127.0.0.1"
ADDR = (SERVER, PORT)
DISCONNECT_MESSAGE = "!DISCONNECT"

# MESSAGE STR SIZE
MSG_LEN = 133340

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # TCP connection
server.bind(ADDR)

# CBF List to store CBFs
cbf_list = []

def handle_client(conn, addr):
    global server
    print(f"[NEW CONNECTION] {addr} connected.")
    connected = True
    while connected:
        # Split message and check for keywords "qbf", "covid" and process accordingly
        # If covid then a cbf is sent
        full_msg = b''

        # Message is split - keeps receiving until full message is given
        while len(full_msg) < MSG_LEN:
            rcv_msg = receive_message(conn)
            if not rcv_msg:
                print(f"Closing connection with {addr}")
                exit(1)
            full_msg += rcv_msg['data']

        # Full message received
        status, bf_b64encoded = full_msg.decode().split("|")
        full_msg = b'' # Reset full message

        # Recreating the Bloom Filter
        bf_bytes = b64decode(bf_b64encoded)
        bf = bitarray()
        bf.frombytes(bf_bytes)

        # Getting list of positions that are 1 bit
        iterator = re.finditer('1', str(bf))
        digestPos = [bit.start(0) for bit in iterator]

        # QBF was received
        if (status == "qbf"):
            print(f"[TASK 10-A] QBF content from {addr}: {digestPos}")
            print(f"Current CBF uploads: {cbf_list}")
            
            # Finding matching CBF
            # CBF is a list inside a list: cbf_list[[cbf1], [cbf2]]
            match = False
            for cbfs in cbf_list:
                for digest in cbfs:
                    if digest in digestPos:
                        # Found matching CBF
                        match = True
                        print(f"[Task 10-C] Found a matching CBF for {addr}: {digest}")
                        send_match_result(conn, "Positive") # Send result to client
                        break
                # Found matching CBF
                if match:
                    break
            
            if not match:
                print(f"[Task 10-C] Did not find matching CBF for {addr}")
                send_match_result(conn, "Negative") # Send result to client

        elif (status == "cbf"):
            # Add CBF content into cbf_list
            print(f"[TASK 9] Uploading CBF content {digestPos} to server")
            cbf_list.append(digestPos)
            print(f"\tCBF content: {cbf_list}")
            send_match_result(conn, "Uploaded") # Send result to client

        print(f"Sending information to {addr}...")

        pass

# This segment of code was borrowed from 
# https://www.techwithtim.net/tutorials/socket-programming/
def start():
    server.listen()
    while True:
        # Accept a connection
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.activeCount()-1}")


print("[STARTING] Server is starting")
start()
