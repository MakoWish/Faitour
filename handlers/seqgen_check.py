# All credit to eightus/Cyder for this one

from scapy.all import IP, TCP, Ether
from utils.config import if_sock
from utils.logger import logger


def seqgen_detect(nfq_packet, packet, fingerprint):
	# ----------------------------------------------------------------------------
	nmap_seq1 = (packet[TCP].window == 1 and packet[TCP].flags == 0x02 and
				 packet[TCP].options == [('WScale', 10), ('NOP', None),
										 ('MSS', 1460), ('Timestamp', (4294967295, 0)),
										 ('SAckOK', b'')])

	nmap_seq2 = (packet[TCP].window == 63 and packet[TCP].flags == 0x02 and
				 packet[TCP].options == [('MSS', 1400), ('WScale', 0),
										 ('SAckOK', b''), ('Timestamp', (4294967295, 0)),
										 ('EOL', None)])

	nmap_seq3 = (packet[TCP].window == 4 and packet[TCP].flags == 0x02 and
				 packet[TCP].options == [('Timestamp', (4294967295, 0)),
										 ('NOP', None), ('NOP', None),
										 ('WScale', 5), ('NOP', None),
										 ('MSS', 640)])

	nmap_seq4 = (packet[TCP].window == 4 and packet[TCP].flags == 0x02 and
				 packet[TCP].options == [('SAckOK', b''),
										 ('Timestamp', (4294967295, 0)),
										 ('WScale', 10), ('EOL', None)])

	nmap_seq5 = (packet[TCP].window == 16 and packet[TCP].flags == 0x02 and
				 packet[TCP].options == [('MSS', 536), ('SAckOK', b''),
										 ('Timestamp', (4294967295, 0)),
										 ('WScale', 10), ('EOL', None)])

	nmap_seq6 = (packet[TCP].window == 512 and packet[TCP].flags == 0x02 and
				 packet[TCP].options == [('MSS', 265), ('SAckOK', b''),
										 ('Timestamp', (4294967295, 0))])

	# ----------------------------------------------------------------------------

	if nmap_seq1:
		logger.debug(f'"type":["info"],"kind":"event","category":["network"],"dataset":"faitour.application","action":"seqgen_detect","reason":"Drop packet for match to \"nmap_seq1\" packet match","outcome":"success"')
		nfq_packet.drop()
		if fingerprint.do_respond['PKT_1']:
			spoofed_packet = craft(packet, fingerprint, '1')
			if_sock.send(spoofed_packet)
			logger.debug(f'"type":["info"],"kind":"event","category":["network"],"dataset":"faitour.application","action":"seqgen_detect","reason":"Sending spoofed packet","outcome":"success"')
		return True

	elif nmap_seq2:
		logger.debug(f'"type":["info"],"kind":"event","category":["network"],"dataset":"faitour.application","action":"seqgen_detect","reason":"Drop packet for match to \"nmap_seq2\" packet match","outcome":"success"')
		nfq_packet.drop()
		if fingerprint.do_respond['PKT_2']:
			spoofed_packet = craft(packet, fingerprint, '2')
			if_sock.send(spoofed_packet)
			logger.debug(f'"type":["info"],"kind":"event","category":["network"],"dataset":"faitour.application","action":"seqgen_detect","reason":"Sending spoofed packet","outcome":"success"')
		return True

	elif nmap_seq3:
		logger.debug(f'"type":["info"],"kind":"event","category":["network"],"dataset":"faitour.application","action":"seqgen_detect","reason":"Drop packet for match to \"nmap_seq3\" packet match","outcome":"success"')
		nfq_packet.drop()
		if fingerprint.do_respond['PKT_3']:
			spoofed_packet = craft(packet, fingerprint, '3')
			if_sock.send(spoofed_packet)
			logger.debug(f'"type":["info"],"kind":"event","category":["network"],"dataset":"faitour.application","action":"seqgen_detect","reason":"Sending spoofed packet","outcome":"success"')
		return True

	elif nmap_seq4:
		logger.debug(f'"type":["info"],"kind":"event","category":["network"],"dataset":"faitour.application","action":"seqgen_detect","reason":"Drop packet for match to \"nmap_seq4\" packet match","outcome":"success"')
		nfq_packet.drop()
		if fingerprint.do_respond['PKT_4']:
			spoofed_packet = craft(packet, fingerprint, '4')
			if_sock.send(spoofed_packet)
			logger.debug(f'"type":["info"],"kind":"event","category":["network"],"dataset":"faitour.application","action":"seqgen_detect","reason":"Sending spoofed packet","outcome":"success"')
		return True

	elif nmap_seq5:
		logger.debug(f'"type":["info"],"kind":"event","category":["network"],"dataset":"faitour.application","action":"seqgen_detect","reason":"Drop packet for match to \"nmap_seq5\" packet match","outcome":"success"')
		nfq_packet.drop()
		if fingerprint.do_respond['PKT_5']:
			spoofed_packet = craft(packet, fingerprint, '5')
			if_sock.send(spoofed_packet)
			logger.debug(f'"type":["info"],"kind":"event","category":["network"],"dataset":"faitour.application","action":"seqgen_detect","reason":"Sending spoofed packet","outcome":"success"')
		return True

	elif nmap_seq6:
		logger.debug(f'"type":["info"],"kind":"event","category":["network"],"dataset":"faitour.application","action":"seqgen_detect","reason":"Drop packet for match to \"nmap_seq6\" packet match","outcome":"success"')
		nfq_packet.drop()
		if fingerprint.do_respond['PKT_6']:
			spoofed_packet = craft(packet, fingerprint, '6')
			if_sock.send(spoofed_packet)
			logger.debug(f'"type":["info"],"kind":"event","category":["network"],"dataset":"faitour.application","action":"seqgen_detect","reason":"Sending spoofed packet","outcome":"success"')
		return True

	else:
		return False


def craft(packet, fingerprint, pkt_number):
	logger.debug(f'"type":["info"],"kind":"event","category":["network"],"dataset":"faitour.application","action":"seqgen_detect","reason":"Craft spoofed packet due to SEQ{pkt_number} packet match","outcome":"success"')
	try:
		ether = Ether()
		ether.dst = packet[Ether].dst
		ether.type = 0x800
	except IndexError:
		ether = None

	ip = IP()
	ip.src = packet[IP].dst
	ip.dst = packet[IP].src
	ip.ttl = int(fingerprint.probe['T1']['TTL'], 16)
	ip.flags = fingerprint.probe['T1']['DF']
	ip.id = fingerprint.ip_id_gen()

	tcp = TCP()

	if_sockval = fingerprint.probe['T1']['S']
	if if_sockval == 'Z':
		tcp.seq = 0
	elif if_sockval == 'A':
		tcp.seq = packet[TCP].ack
	elif if_sockval == 'A+':
		tcp.seq = packet[TCP].ack + 1
	else:
		tcp.seq = fingerprint.tcp_seq_gen()

	a_val = fingerprint.probe['T1']['A']
	if a_val == 'Z':
		tcp.ack = 0
	elif a_val == 'S':
		tcp.ack = packet[TCP].seq
	elif a_val == 'S+':
		tcp.ack = packet[TCP].seq + 1
	else:
		tcp.ack = packet[TCP].seq + 369

	flag_val = fingerprint.probe['T1']['F']
	tcp.flags = flag_val

	tcp.window = fingerprint.probe['WIN']['W' + pkt_number]

	tcp.sport = packet[TCP].dport
	tcp.dport = packet[TCP].sport

	tcp.options = fingerprint.probe['OPS']['O' + pkt_number]

	rd_val = fingerprint.probe['T1']['RD']
	if rd_val != '0':
		crc = int(rd_val, 16)
		data = b'TCP Port is closed\x00'
		data += compensate(data, crc)
		response = ip / tcp / data if ether is None else ether / ip / tcp / data

	else:
		response = ip / tcp if ether is None else ether / ip / tcp

	# Return our crafted response
	return response


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
