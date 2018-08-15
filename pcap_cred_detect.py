# Credential Harvesting POST Submission Detection
# Author: Heferyzan
#
# This script reads PCAP files and searches for HTTP POST messages that contain potential user credentials 
# 
# Usage: python pcap_cred_detect.py -f pcap.pcapng
#
# Requirements: scapy from https://github.com/secdev/scapy
# Install scapy: sudo python setup.py install
#

import argparse
import sys
from scapy.all import *
import re

def arg_parse():
	parser=argparse.ArgumentParser()
	parser.add_argument('-f', dest='file_name', help='type the pcap filename', action='store', required=True)
	args = parser.parse_args()
	return args.file_name

def pcap_parse(pcap_file): 
	packet_sessions = pcap_file.sessions()
	for session in packet_sessions:
		for packet in packet_sessions[session]:
			try:
				if packet[TCP].dport == 80 and "POST" in str(packet):
					http_data = bytes(packet[Raw])
					domain = re.findall(r"Host: (.*?)\r\n", http_data)
					credentials = re.findall(r"(?:username|email|user|usrname)\=([\w][\S][^&]+)&.*?(?:password|passwd|pass|pwd)=([\S][^&]+)", http_data)
					if credentials and [item for item in credentials]:
						print "Username '%s' submitted password '%s' to domain '%s'" % (item[0], item[1], domain[0])
			except:
				pass

def main(file_name):
	packets = rdpcap(file_name)
	pcap_parse(packets)

if __name__ == "__main__":
	arguments = arg_parse()
	main(arguments)