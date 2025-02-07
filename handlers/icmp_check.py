# All credit to eightus/Cyder for this one

import random
from scapy.all import IP, ICMP, Raw, Ether
from utils.config import if_sock


def icmp_detect(nfq_packet, packet, fingerprint):

	nmap_icmp1 = (packet[ICMP].type == 8 and
				  packet[ICMP].seq == 295 and packet[ICMP].code == 9 and
				  packet[IP].tos == 0 and packet[IP].flags == 2 and len(packet[Raw].load) == 120)

	nmap_icmp2 = (packet[ICMP].type == 8 and
				  packet[ICMP].seq == 296 and packet[ICMP].code == 0 and
				  packet[IP].tos == 4 and
				  packet[IP].flags == 0 and len(packet[Raw].load) == 150)

	nmap_icmp3 = (packet[ICMP].type == 8)
	# ----------------------------------------------------------------------------

	if nmap_icmp1 or nmap_icmp2:
		nfq_packet.drop()
		if fingerprint.do_respond['IE']:
			if_sock.send(craft(packet, fingerprint))
		return True
	elif nmap_icmp3:
		nfq_packet.drop()
		if fingerprint.do_respond['IE']:
			if_sock.send(craft(packet, fingerprint))
		return True
	else:
		return False


def craft(packet, fingerprint):
	try:
		ether = Ether()
		ether.dst = packet[Ether].dst
		ether.type = 0x800
	except IndexError:
		ether = None

	ip = IP()
	ip.src = packet[IP].dst
	ip.dst = packet[IP].src
	ip.ttl = int(fingerprint.probe['IE']['TTL'], 16)
	dfi_flag = fingerprint.probe['IE']['DFI']
	if dfi_flag == 'N':
		ip.flags = 0
	elif dfi_flag == 'S':
		ip.flags = packet[IP].flags
	elif dfi_flag == 'Y':
		ip.flags = 2
	else:
		ip.flags = 0 if packet[IP].flags == 2 else 2

	ip.id = fingerprint.ip_id_icmp_gen()
	icmp = ICMP()
	icmp.type = 0
	icmp.id = packet[ICMP].id

	cd_val = fingerprint.probe['IE']['CD']
	if cd_val == 'Z':
		icmp.code = 0
	elif cd_val == 'S':
		icmp.code = packet[ICMP].code
	else:
		icmp.code = random.randint(0, 15)

	icmp.seq = packet[ICMP].seq
	data = packet[ICMP].payload

	fin_packet = ip / icmp / data if ether is None else ether / ip / icmp / data
	return fin_packet

