# All credit to eightus/Cyder for this one

from scapy.all import IP, ICMP, Raw, UDP, IPerror, UDPerror, Ether
from utils.config import if_sock


def udp_detect(nfq_packet, packet, fingerprint):
	# ----------------------------------------------------------------------------
	nmap_udp = (packet[IP].id == 0x1042 and
							 len(packet[Raw].load) == 300 and
							 packet[Raw].load == 300 * b'C')

	# ----------------------------------------------------------------------------

	if nmap_udp:
#		print("Drop for nmap_udp")
		nfq_packet.drop()
		if fingerprint.do_respond['U1']:
			if_sock.send(craft(packet, fingerprint))
		return True
	else:
		return False


def craft(packet, fingerprint):
#	print("Craft UDP")
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
	ip.ttl = int(fingerprint.probe['U1']['TTL'], 16)
	ip.flags = fingerprint.probe['U1']['DF']
	ip.len = 56
	ip.id = 4162

	icmp = ICMP()
	icmp.type = 3
	icmp.unused = 0
	icmp.code = 13  # code 3 for reply

	iperror = IPerror()
	iperror.proto = 'udp'
	iperror.ttl = 0x3E
	iperror.len = fingerprint.probe['U1']['RIPL']
	iperror.id = fingerprint.probe['U1']['RID']

	ripck_val = fingerprint.probe['U1']['RIPCK']
	if ripck_val == 'G':
		pass
	elif ripck_val == 'Z':
		iperror.chksum = 0
	else:
		iperror.chksum = packet[IP].chksum

	udperror = UDPerror()
	udperror.sport = packet[UDP].sport
	udperror.dport = packet[UDP].dport
	udperror.len = packet[UDP].len
	if fingerprint.probe['U1']['RUCK'] == 'G':
		udperror.chksum = packet[UDP].chksum
	else:
		udperror.chksum = fingerprint.probe['U1']['RUCK']

	try:
		ipl = int(fingerprint.probe['U1']['IPL'], 16)
	except KeyError:
		ipl = None

	data = packet[Raw].load

	fin_packet = ip / icmp / iperror / udperror / data if ether is None else ether / ip / icmp / iperror / udperror / data

	return fin_packet
