from scapy.all import *
from utils.logger import logger
import utils.config as config


#===============================================================================
# Check if TCP packet looks like an NMAP scan on a monitored service
#===============================================================================
def tcp(packet):
	tcp = packet[TCP]
	ip = packet[IP]

#	syn_pattern = (tcp.flags == "S" and tcp.dport in config.enabled_ports and tcp.ack == 0)
#	ack_pattern = (tcp.flags == "A" and tcp.dport in config.enabled_ports and tcp.seq == tcp.ack)

	# If this port/service is to be spoofed, return True
	#if syn_pattern or ack_pattern:
#	if tcp.dport in config.enabled_ports:
#		# Temporarily only work with one source IP for testing
#		if ip.src == "192.168.200.25":
#			logger.debug(f"Packet Details:\n{packet.show2(dump=True)}")
#			return True

	return False


#===============================================================================
# Check if UDP packet looks like an NMAP scan on a monitored service
#===============================================================================
def is_nmap_udp(packet):
	#logger.debug(f"Packet Details:\n{packet.show2(dump=True)}")
	return False


#===============================================================================
# Check if ICMP packet looks like an NMAP ICMP ping
#===============================================================================
def is_nmap_icmp(packet):
	icmp = packet[ICMP]
	ip = packet[IP]

#	logger.debug(f"Packet Details:\n{packet.show2(dump=True)}")
	
#	if (icmp.type == 8 or icmp.type == 13) and icmp.code == 0:
#		payload = bytes(icmp.payload)
#		if payload == b'':  # All my testing shows NMAP pings to have an empty payload
#			logger.debug(f"ICMP ping from {ip.src} to {ip.dst} appears to be NMAP.")
#			return True
#		else:
#			logger.debug(f"ICMP ping from {ip.src} to {ip.dst} is not NMAP.")
#			return False

	return False
