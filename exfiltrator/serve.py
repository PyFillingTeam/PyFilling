import argparse
import dns_exfil
import pop_exfil_server3
import icmp_exfil_server3
import ntp_exfil
import http_server
import sys

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--address", type=str)
    parser.add_argument("-i", "--protocol", type=str)
    parser.add_argument("-s", "--size", type=int)
    args = parser.parse_args()
    
    if args.protocol.lower() == "dns":
        dns_exfil.dns_server(host=args.address)
    elif args.protocol.lower() == "pop3":
        pop_exfil_server3.start_server(args.address)
    elif args.protocol.lower() == "icmp":
        icmp_exfil_server3.start_listener(args.address)
    elif args.protocol.lower() == "ntp":
        ntp_exfil.ntp_listener(ip=args.address, MAX_BYTES=args.size)
    elif args.protocol.lower() == "http":
        http_server.run(host=args.address)
    
    print(args.protocol)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Key Interrupt")
        sys.exit(0)