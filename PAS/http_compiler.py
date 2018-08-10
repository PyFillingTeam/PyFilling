#!/usr/bin/env python3

import base64

def read_cookies(logs):
    
    filename = ''
    binary = ''
    
    with open(logs, 'r') as log_file:
        for line in log_file:
            #check if entry is relevant
            if "cookies" and "ID" in line:
                data = line.split('=', 2)[2][:-3]
                #check for iniation cookie
                if "sessionID" in line:
                    tail = data.find("..")
                    filename = data[:tail]
                #check for termination cookie
                elif "sessID0" in line:
                    compile(filename, binary)
                #check for data cookie
                elif 'PHPSESSID' in line:
                    binary += data
                #cookie is not relevant
                else:
                    #clear data
                    filename = ''
                    binary = ''
            else:
                #clear data
                filename = ''
                binary = ''

def compile(filename, data):
    file = base64.b64decode(data)
    fh = open(filename, "wb")
    fh.write(file)
    fh.close()
    print("\nFile Extracted\n")

if __name__ == '__main__':
    print("Enter log file to parse")
    path = input()
    read_cookies(path)