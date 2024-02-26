from binascii import hexlify
import socket
from base64 import b64encode, b64decode
from time import sleep # This is used because you can't use .encode() on qbf. 

HEADER_SIZE = 20

server = "127.0.0.1"
port = 55000
addr = (server,port)

# TASK 1: Printing generated EphID
def print_id(id):
    print(f"\n[TASK 1]: Generate 16 byte ID {hexlify(id)} len: {len(id)}")

# Binding message -> lets receiving TCP connection know how long the message is
def bind_message(msg):
    return f"{len(msg):<{HEADER_SIZE}}" + msg

# Sending bloom filters to server
def send_bf(client, bf, keyword):
    bf_str = b64encode(bf).decode()
    message_string_full = keyword + bf_str # Keyword = cbf or qbf
    message_split = []

    # Splitting message to 4 equal parts to not overload TCP sending
    for i in range(4):
        message_split.append(message_string_full[i * 33335: (i + 1) * 33335])
    
    # Bind message with header and send to server
    for i in range(4):
        message_send = bind_message(message_split[i])
        
        client.send(message_send.encode())
        sleep(0.5) # Don't send too continuously or it might break

# Sending results from server to client
def send_match_result(server_socket, result):
    msg = bind_message(result)
    msg_enc = msg.encode()
    server_socket.send(msg_enc)

# Used when TCP connection received a message
def receive_message(client_socket):
    try:
        msg = client_socket.recv(HEADER_SIZE)
        if not len(msg):
            # Nothing in message
            return False

        msg_len = int(msg.decode('utf-8'))
        return {'header': msg, 'data': client_socket.recv(msg_len)}

    # Couldn't receive message properly
    except Exception as e:
        print(f"Exception error: {e}")
        return False

# Asking if client is COVID positive to send QBF or CBF
def client_covid_response():
    question_string = "If you are COVID-19 positive, would you like to notify\n"
    question_string += "your close contacts? (Y/N)\n"
    question_string += "Answer 'N' if you are COVID-19 negative: "
    proper_answer = False # This is in case the user entered something random
    covid = False
    while not proper_answer:
        given_answer = input(question_string).strip()
        ans = given_answer.upper() 
        if ans == 'Y':
            proper_answer = True
            covid = True
        elif ans == 'N':
            proper_answer = True
        else: 
            print("Please enter Y or N as the response.")
    return covid
