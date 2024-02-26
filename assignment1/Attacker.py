from audioop import add
from binascii import hexlify, unhexlify
import random
import socket
from ssl import SOL_SOCKET
import threading
from helper import print_id, receive_message, send_bf, client_covid_response
from ephID import *
from bloom import *
import time
from hashlib import sha256
from Crypto.Protocol.SecretSharing import Shamir
from copy import deepcopy

# TIME DEFS
ID_TIMER = 15 # 15s
BROADCAST_TIMER = 3 # 3s
DBF_TIMER = 90 # 90s
QBF_TIMER = 540 # 9min = 540s

# This private key will also be used in DH (Diffie-Hellman)
ecdh = generate_ephID_ECDH()
port = 56000 # Clients UDP port changed to 56000
private_key_hash = 0
server = "127.0.0.1"
addr = (server, port)
dimy_server_addr = (server, 55000)
old_hash = 0
filter_size = 800000 # 800,000 bits = 100 KB
dbf = BloomFilter(filter_size)
dbf_list = []
exit_program = False

client_tcpsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # TCP connection
client_tcpsocket.connect(dimy_server_addr)

print(f"Starting client in port {port}")

def create_new_ephID(ecdh):
    # global private_key
    new_ephid = generate_ephID_public_key(ecdh)
    # eph_ID_toString = ephID_to_string(new_ephid)
    hexlify_id = hexlify(new_ephid) + "00".encode() ## Removing the two 0 padding
    new_ephid = unhexlify(hexlify_id)
    print_id(new_ephid)
    # Private key hash -> This is because the private key is used to create the chunks
    # And because you can't hash broadcast_chunks because it's not a bytes string
    private_key_hash = sha256(new_ephid).hexdigest()
    #print(private_key_hash)

    # Create 5 chunks to broadcast
    broadcast_chunks = Shamir.split(3, 5, new_ephid)

    return private_key_hash, broadcast_chunks

def compute_encID(ecdh, key):
    hexlify_key = hexlify(key).decode()
    new_key = hexlify_key[:-2] # Removing the two 00 padding
    new_key = new_key.encode()
    print(f"Original Key: {new_key}")
    unhexlify_key = unhexlify(new_key) # This should be the original key

    encID = create_sharedsecret_key(ecdh, unhexlify_key)

    return encID

# thread to start the broadcasting
def udp_broadcaster():
    global ecdh, port, server, addr, private_key_hash, old_hash, exit_program
    # global private_key, private_key_hash, port, server, addr
    # Create a socket
    broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

    #broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Enable broadcast mode
    broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    # Create a new ephID
    private_key_hash, broadcast_chunks = create_new_ephID(ecdh)

    for i in range(5):
        print(f"\n[TASK 2] Shares created: {broadcast_chunks[i][0]} | {hexlify(broadcast_chunks[i][1])} | {private_key_hash}" )

    # Initialise timers
    start_time = time.time()
    id_timer = ID_TIMER
    curr_time = start_time - time.time()
    broadcast_timer = BROADCAST_TIMER

    # Send a message 
    while not exit_program:

        # Change 5 shares every 3 seconds
        if curr_time > broadcast_timer:
            # Need to send to send 1 unique share every 3 seconds - Done
            #print(f"[TASK 3] Broadcast shares: {broadcast_chunks[0][0]} | {hexlify(broadcast_chunks[0][1])}") #| {private_key_hash}")
            broadcast_string = str(broadcast_chunks[0][0]) + '|' + hexlify(broadcast_chunks[0][1]).decode() +'|'+ private_key_hash
            task3a_rand_num_gen = random.random()
            if task3a_rand_num_gen >= 0.5:
                broadcast_socket.sendto(broadcast_string.encode(), addr)
                print(f"\n[TASK 3-A] Broadcast share using drop mechanism: {broadcast_chunks[0]} | {hexlify(broadcast_chunks[0][1])} | {private_key_hash}")
            broadcast_chunks.pop(0)
            #broadcast_socket.sendto(broadcast_string, addr)

            broadcast_timer += BROADCAST_TIMER
        # Generate a new ephID every 15 seconds
        elif curr_time > id_timer:
            old_hash = private_key_hash
            private_key_hash, broadcast_chunks = create_new_ephID(ecdh)
            # private_key = generate_ephid()
            # private_key_hash = sha256(private_key).hexdigest()
            # broadcast_chunks = Shamir.split(3, 5, private_key)
            # print_id(private_key)

            for i in range(5):
                print(f"\n[TASK 2] Shares created: {broadcast_chunks[i][0]} | {hexlify(broadcast_chunks[i][1])} | {private_key_hash}" )
            # update id_timer
            id_timer += ID_TIMER
            
            # update timer
        curr_time = time.time() - start_time

    exit(1)

def udp_receiver():
    # create socket
    global ecdh, private_key_hash, exit_program
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) #socket.IPPROTO_UDP))

    # Don't reuse the socket for receiving as broadcasting since the client will receive its own packets and not from a different client.
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    # server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Commented this out and it worked.
    #server.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST,1)
    server.bind(addr)

    print("Waiting for shares from clients")
    print()

    received_chunks = {}
    # Dictionary = {hash : [list of SSS received]}
    while not exit_program:
        # Receive the message and the addr that it's from
        recv_msg, client_addr = server.recvfrom(2048)
        recv_index, recv_chunk, recv_hash = recv_msg.decode().split('|')
        #print(f"recv index {recv_index}, recv_chunk {unhexlify(recv_chunk.encode())}, recv_hash {recv_hash}")
        
        recv_index = int(recv_index)

        print("")
        if (recv_hash == private_key_hash or recv_hash == old_hash):
            continue
        else:
            recv_index_chunk = (recv_index, unhexlify(recv_chunk.encode()))
            if recv_hash not in received_chunks:
                received_chunks[recv_hash] = [recv_index_chunk]
            elif recv_index_chunk not in received_chunks[recv_hash]:
                received_chunks[recv_hash].append(recv_index_chunk)

            # 3-B and 3-C Receive shares from other nodes, Show that you are keeping track of number of shares received for each EphID
            num_recv_shares = len(received_chunks[recv_hash])

            print(f"\n[TASK 3-C] Number of received shares from {client_addr} shares: {num_recv_shares} for {recv_hash}")
            print(f"Received chunks: {received_chunks[recv_hash]}")
            if num_recv_shares >= 3:

                key = Shamir.combine(received_chunks[recv_hash])
                print(f"\n[TASK 4-A] Reconstruction of EphID: {hexlify(key)}")
                # ephid was hashed using sha256
                print(f"\n[TASK 4-B] Take hash of reconstructed EphID (sha256) and compare it to the received hash (recv_hash)") 
                new_hash = sha256(key).hexdigest()
                print(f"Hash of reconstructed EphID: {new_hash}")
                print(f"Hash of received hash: {recv_hash}")
                if (new_hash == recv_hash):
                    print("Hash has been identified, Computing EncID")
                    encID = compute_encID(ecdh, key)
                    print(f"\n[TASK 5-A] Computed EncID using Diffie-Hellman key exchange: {hexlify(encID)}")
                    print("\n[TASK 6] Adding EncID to DBF")
                    dbf.add(str(encID))
                    print("")
                    #dbf.check(str(encID))
                    print("\n[TASK 7-A] Current state of DBF")
                    print(dbf.get_DigestPos())
                    print("")
    
    exit(1)

# This thread is meant to send the qbf
def tcp_sender():
    global dbf, dbf_list, filter_size, client_tcpsocket
    # client_tcpsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # TCP connection
    # client_tcpsocket.connect(dimy_server_addr)

    # Initialise empty qbf
    qbf = BloomFilter(filter_size)

    start_time = time.time()
    dbf_timer = DBF_TIMER
    qbf_timer = QBF_TIMER 
    curr_time = time.time() - start_time

    # QBF generation generation is stopped when the client says they have covid
    # Added a global variable called covid that checks if the client has covid

    while True:
        # if the current time is past the dbf timer, append a new dbf
        if curr_time > dbf_timer:
            # Check if the size of dbf_list is == 6, if it is, then pop the oldest dbf
            if len(dbf_list) == 6:
                dbf_list.pop(0)
            # Append the new dbf to dbf_list
            print("Appending DBF to dbf_list")
            dbf_list.append(deepcopy(dbf))
            print("\n[TASK 7-B] Creating a new DBF\n")
            # Reset the old dbf
            dbf.reset()
            dbf_timer += DBF_TIMER
            # Asking if the client is COVID positive
            covid = client_covid_response()
            if covid:
                break # Client has covid. Don't send QBF
        if curr_time > qbf_timer:
            qbf.merge(dbf_list)
            print(f"\n[TASK 8] Creating QBF: {qbf.get_DigestPos()}")
            print(f"\n[TASK 10-A] Sending QBF to server...")
            send_bf(client_tcpsocket, qbf.bit_array, "qbf|")
            qbf.reset()
            qbf_timer += QBF_TIMER

    	# update timer
        curr_time = time.time() - start_time


    # Combining all available DBF into a CBF
    cbf = BloomFilter(filter_size) # Creating CBF
    cbf.merge(dbf_list)
    # Sending to server as CBF
    print(f"\n[TASK 9] Sending CBF to server...")
    send_bf(client_tcpsocket, cbf.bit_array, "cbf|")
    exit(1)

# Used to receive server messages
def tcp_receiver():
    global client_tcpsocket, exit_program
    ######################################################
    while True:
        server_msg = receive_message(client_tcpsocket)
        result = server_msg['data'].decode()

        if result == "Uploaded":
            print(f"\n[TASK 10-B]: Server upload response: {result} successfully")
            print("Stay at home for recommended period. Get well soon!")
            exit_program = True
            exit(1)
        else:
            print(f"\n[TASK 10-B]: Results from server: {result} match")


# Thread to receive chunks
udp_receiver_thread = threading.Thread(name = "ClientUDPReceiver", target = udp_receiver)
udp_receiver_thread.start()

#Thread to send qbf
tcp_sender_thread = threading.Thread(name = "ClientTCPSender", target = tcp_sender)
tcp_sender_thread.start()

tcp_receiver_thread = threading.Thread(name = "ClientTCPReceiver", target = tcp_receiver)
tcp_receiver_thread.start()


# UDP flooding attack method
# How it works:
# Start up 50 threads that broadcasts to the UDP port.
# Other clients connected to this port will experience a "flood" of UDP broadcasts and will eventually crash due to duplicate shares being received.
threads = []

if __name__ == '__main__':
    for i in range(50):
        t = threading.Thread(name = "ClientUDPBroadcaster", target = udp_broadcaster)
        t.daemon = True
        threads.append(t)

    for i in range(50):
        threads[i].start()

    for i in range(50):
        threads[i].join()
        