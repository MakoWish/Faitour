import socket
import random
import utils.config as config
from utils.logger import logger
from scapy.all import *


#===============================================================================
# Return a spoofed TCP packet to the requestor
#===============================================================================
def tcp(nfq_packet, packet):
	if packet[TCP].flags == "S":
		client_ip = packet[IP].src
		client_port = packet[IP].dport
		logger.debug(f"Spoof a SYN/ACK response to {packet[IP].src} from port {packet[TCP].dport}.")
		logger.debug(f'"type":["connection","allowed","start"],"kind":"alert","category":["network","intrusion_detection"],"dataset":"honeypot","action":"tcp","reason":"Spoof a SYN/ACK response","outcome":"success"}},"source":{{"ip":"{client_ip}","port":{client_port}')
		syn_ack(packet)
		nfq_packet.drop()
	#elif packet[TCP].flags == "A":
	#	logger.debug(f"Spoof a full response to {packet[IP].src} from port {packet[TCP].dport}.")
	#	syn_ack(packet, True)
	#	nfq_packet.drop()
	else:
		nfq_packet.accept()

	return True


#===============================================================================
# Return a spoofed UDP packet to the requestor
#===============================================================================
def udp(nfq_packet, packet):
	nfq_packet.accept()
	return True


#===============================================================================
# Return a spoofed ICMP packet to the requestor
#===============================================================================
def icmp(nfq_packet, packet):
	# Clone the packet
	modified_packet = packet.copy()
	
	# Modify the TTL as a proof of concept
	modified_packet[IP].ttl = 65

	# Reverse the packet direction as a response
	modified_packet[IP].src = packet[IP].dst
	modified_packet[IP].dst = packet[IP].src
	
	# Recalculate checksums
	del modified_packet[IP].chksum
	del modified_packet[ICMP].chksum

	# Drop the original nfqueue packet
	nfq_packet.drop()
	
	# Show the modified packet before sending
	logger.debug(f'"type":["info"],"kind":"event","category":["process"],"dataset":"application","action":"icmp","reason":"Modified and forwarded packet: {modified_packet.summary()}","outcome":"success"')

	# Use our global socket to send the spoofed packet
	config.if_sock.send(modified_packet)


#===============================================================================
# Send a simple ACK to a received SYN
#===============================================================================
def syn_ack(packet, fingerprint=False):
	# Create an Ether layer if we have info for it
	if packet.haslayer(Ether):
		ether = Ether()
		ether.src = packet[Ether].dst
		ether.dst = packet[Ether].src
		ether.type = 0x800
	else:
		ether = None

	# Create an IP layer
	ip = IP()
	ip.src = packet[IP].dst
	ip.dst = packet[IP].src
	ip.ttl = packet[IP].ttl
	ip.flags = 0x4000
	ip.id = random.randint(1, 1000)

	# Create a TCP layer
	tcp = TCP()
	tcp.sport = packet[TCP].dport
	tcp.dport = packet[TCP].sport

	if fingerprint:
		tcp.flags = 0x018  # PSH / ACK
		tcp.seq = packet[TCP].seq
		tcp.ack = packet[TCP].ack
		data = config.get_fingerprint(packet[TCP].dport)
		response = ip / tcp / data if ether is None else ether / ip / tcp / data
	else:
		tcp.flags = 0x012  # SYN / ACK
		tcp.seq = packet[TCP].seq
		tcp.ack = packet[TCP].seq + 1
		response = ip / tcp if ether is None else ether / ip / tcp

	# Send out spoofed response
	config.if_sock.send(response)


#===============================================================================
# Check to see if a local port is already listening
#===============================================================================
def port_is_listening(port: int) -> bool:
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
		sock.settimeout(1)  # Set timeout for the connection attempt
		try:
			sock.connect(("localhost", port))
			return True
		except (socket.timeout, ConnectionRefusedError):
			return False



def sample_packet_modifications(nfq_packet, packet):
	# Check if the packet has an IP layer (most packets will have this)
	if packet.haslayer(IP):
		ip = packet[IP]

		# Modify packet (Example: Change destination IP to a different address)
		new_dst = "192.168.1.100"  # New destination IP
		ip.dst = new_dst  # Modify destination IP

		# If it's a TCP packet, modify source port or destination port
		if packet.haslayer(TCP):
			tcp = packet[TCP]
			tcp.sport = 12345  # Change source port (example)
			tcp.dport = 80     # Change destination port (example)

		# If it's a UDP packet, modify source port or destination port
		elif packet.haslayer(UDP):
			udp = packet[UDP]
			udp.sport = 12345  # Change source port (example)
			udp.dport = 53     # Change destination port (example)

		# Recalculate checksums for modified packet
		del packet[IP].len
		del packet[IP].chksum
		if packet.haslayer(TCP):
			del packet[TCP].chksum
		if packet.haslayer(UDP):
			del packet[UDP].chksum

		# Send the modified packet to the new destination
		logger.debug(f'"type":["info"],"kind":"event","category":["process"],"dataset":"application","action":"icmp","reason":"Forwarding modified packet to {new_dst}","outcome":"success"')
		send(packet)  # Forward the packet


def get_services():
	# Get configured services from config
	return 0


def get_os():
	# Get the operating system from config
	return 0
