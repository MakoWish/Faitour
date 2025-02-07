# All credit to eightus/Cyder for this one

import random
from scapy.all import IP, TCP, Ether
from utils.config import if_sock


def t2tot7_detect(nfq_packet, packet, fingerprint):
	# ----------------------------------------------------------------------------
	nmap_t2 = (packet[TCP].window == 128 and packet[TCP].flags == 0x00 and
							 packet[IP].flags == 2 and
							 packet[TCP].options == [('WScale', 10), ('NOP', None),
											   ('MSS', 265), ('Timestamp', (4294967295, 0)),
											   ('SAckOK', b'')])

	nmap_t3 = (packet[TCP].window == 256 and packet[TCP].flags == 0x02b and
							 packet[TCP].options == [('WScale', 10), ('NOP', None),
												  ('MSS', 265), ('Timestamp', (4294967295, 0)),
												  ('SAckOK', b'')])

	nmap_t4 = (packet[TCP].window == 1024 and packet[TCP].flags == 0x010 and
							 packet[IP].flags == 2 and
							 packet[TCP].options == [('WScale', 10), ('NOP', None),
												  ('MSS', 265), ('Timestamp', (4294967295, 0)),
												  ('SAckOK', b'')])

	nmap_t5 = (packet[TCP].window == 31337 and packet[TCP].flags == 0x002 and
							 packet[TCP].options == [('WScale', 10), ('NOP', None),
												  ('MSS', 265), ('Timestamp', (4294967295, 0)),
												  ('SAckOK', b'')])

	nmap_t6 = (packet[TCP].window == 32768 and packet[TCP].flags == 0x010 and
							 packet[IP].flags == 2 and
							 packet[TCP].options == [('WScale', 10), ('NOP', None),
												  ('MSS', 265), ('Timestamp', (4294967295, 0)),
												  ('SAckOK', b'')])

	nmap_t7 = (packet[TCP].window == 65535 and packet[TCP].flags == 0x029 and
							 packet[TCP].options == [('WScale', 15), ('NOP', None),
												  ('MSS', 265), ('Timestamp', (4294967295, 0)),
												  ('SAckOK', b'')])

	# ----------------------------------------------------------------------------

	if nmap_t2:
#		print("Drop for nmap_t2")
		nfq_packet.drop()
		if fingerprint.do_respond['T2']:
			if_sock.send(craft(packet, fingerprint, 'T2'))
		return True

	elif nmap_t3:
#		print("Drop for nmap_t3")
		nfq_packet.drop()
		if fingerprint.do_respond['T3']:
			if_sock.send(craft(packet, fingerprint, 'T3'))
		return True

	elif nmap_t4:
#		print("Drop for nmap_t4")
		nfq_packet.drop()
		if fingerprint.do_respond['T4']:
			if_sock.send(craft(packet, fingerprint, 'T4'))
		return True

	elif nmap_t5:
#		print("Drop for nmap_t5")
		nfq_packet.drop()
		if fingerprint.do_respond['T5']:
			if_sock.send(craft(packet, fingerprint, 'T5'))
		return True

	elif nmap_t6:
#		print("Drop for nmap_t6")
		nfq_packet.drop()
		if fingerprint.do_respond['T6']:
			if_sock.send(craft(packet, fingerprint, 'T6'))
		return True

	elif nmap_t7:
#		print("Drop for nmap_t7")
		nfq_packet.drop()
		if fingerprint.do_respond['T7']:
			if_sock.send(craft(packet, fingerprint, 'T7'))
		return True

	else:
		return False


def craft(packet, fingerprint, t_number):
#	print(f"Craft {t_number}")
	try:
		ether = Ether()
		ether.dst = packet[Ether].dst
		ether.type = 0x800
	except IndexError:
		ether = None

	ip = IP()
	ip.src = packet[IP].dst
	ip.dst = packet[IP].src
	ip.ttl = int(fingerprint.probe[t_number]['TTL'], 16)
	ip.flags = fingerprint.probe[t_number]['DF']
	ip.id = random.randint(1, 1000)

	tcp = TCP()

	if_sockval = fingerprint.probe[t_number]['S']
	if if_sockval == 'Z':
		tcp.seq = 0
	elif if_sockval == 'A':
		tcp.seq = packet[TCP].ack
	elif if_sockval == 'A+':
		tcp.seq = packet[TCP].ack + 1
	else:
		tcp.seq = packet[TCP].ack + 369

	a_val = fingerprint.probe[t_number]['A']
	if a_val == 'Z':
		tcp.ack = 0
	elif a_val == 'S':
		tcp.ack = packet[TCP].seq
	elif a_val == 'S+':
		tcp.ack = packet[TCP].seq + 1
	else:
		tcp.ack = packet[TCP].seq + 369

	flag_val = fingerprint.probe[t_number]['F']
	tcp.flags = flag_val

	w_val = fingerprint.probe[t_number]['W']
	if w_val == 'ECHOED':
		tcp.window = packet[TCP].window
	else:
		tcp.window = w_val

	tcp.sport = packet[TCP].dport
	tcp.dport = packet[TCP].sport

	o_val = fingerprint.probe[t_number]['O']
	if o_val == 'EMPTY':
		pass
	else:
		tcp.options = o_val

	rd_val = fingerprint.probe[t_number]['RD']
	if rd_val != '0':
		crc = int(rd_val, 16)
		data = b'TCP Port is closed\x00'
		data += compensate(data, crc)
		fin_packet = ip / tcp / data if ether is None else ether / ip / tcp / data
	else:
		fin_packet = ip / tcp if ether is None else ether / ip / tcp

	return fin_packet

def compensate(buf, wanted):
	wanted ^= FINALXOR

	newBits = 0
	for i in range(32):
		if newBits & 1:
		   newBits >>= 1
		   newBits ^= CRCPOLY
		else:
		   newBits >>= 1

		if wanted & 1:
		   newBits ^= CRCINV

		wanted >>= 1

	newBits ^= crc32(buf) ^ FINALXOR
	return pack('<L', newBits)
