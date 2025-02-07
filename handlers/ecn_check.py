# All credit to eightus/Cyder for this one

from scapy.all import IP, TCP, Ether
from utils.config import if_sock


def ecn_detect(nfq_packet, packet, fingerprint):
	# ----------------------------------------------------------------------------
	nmap_ecn = (packet[TCP].window == 3 and packet[TCP].flags == 0xc2 and
				packet[TCP].urgptr == 0xF7F5 and
				packet[TCP].options == [('WScale', 10), ('NOP', None),
										('MSS', 1460), ('SAckOK', b''),
										('NOP', None), ('NOP', None)])

	# ----------------------------------------------------------------------------

	if nmap_ecn:
#		print("Drop for nmap_ecn")
		nfq_packet.drop()
		if fingerprint.do_respond['ECN']:
			if_sock.send(craft(packet, fingerprint))
		return True
	else:
		return False


def craft(packet, fingerprint):
#	print("Craft ECN")
#	packet.show()
	try:
		ether = Ether()
		ether.dst = packet[Ether].dst
		ether.type = 0x800
	except IndexError:
		ether = None

	ip = IP()
	ip.src = packet[IP].dst
	ip.dst = packet[IP].src
	ip.ttl = int(fingerprint.probe['ECN']['TTL'], 16)

	ip_flag = fingerprint.probe['ECN']['DF']
	if ip_flag == 'Y':
		ip.flags = 2
	else:
		ip.flags = 0
	ip.id = fingerprint.ip_id_gen()

	tcp = TCP()
	w_val = fingerprint.probe['ECN']['W']
	if w_val == 'ECHOED':
		tcp.window = packet[TCP].window
	else:
		tcp.window = w_val
	tcp.sport = packet[TCP].dport
	tcp.dport = packet[TCP].sport

	cc_val = fingerprint.probe['ECN']['CC']
	if cc_val == 'Y':
		tcp.flags = 0x52
	elif cc_val == 'N':
		tcp.flags = 0x12
	elif cc_val == 'S':
		tcp.flags = 0xD2
	else:
		tcp.flags = 0x10

	o_val = fingerprint.probe['ECN']['O']
	if o_val == 'EMPTY':
		pass
	else:
		tcp.options = o_val

	fin_packet = ip / tcp if ether is None else ether / ip / tcp

	return fin_packet
