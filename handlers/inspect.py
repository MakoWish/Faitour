import utils.config as config
from utils.logger import appLogger
from utils.logger import honeyLogger
from utils.fingerprint import fingerprint
from handlers.ecn_check import ecn_detect
from handlers.udp_check import udp_detect
from handlers.icmp_check import icmp_detect
from handlers.seqgen_check import seqgen_detect
from handlers.t2tot7_check import t2tot7_detect


class Inspect:
	def __init__(self):
		# Generate fingerprint and probe dictionaries
		self.fingerprint = fingerprint
		self.probe = self.fingerprint.probe

	# Return an instance of this class
	def get_inspector(self):
		return self

	# Check if TCP packet matches an OS probe
	def is_tcp_os_probe(self, nfq_packet, packet):
		if seqgen_detect(nfq_packet, packet, self.fingerprint):
			return True
		elif ecn_detect(nfq_packet, packet, self.fingerprint):
			return True
		elif t2tot7_detect(nfq_packet, packet, self.fingerprint):
			return True
		else:
			return False

	# Check if UDP packet matches an OS probe
	def is_udp_os_probe(self, nfq_packet, packet):
		if udp_detect(nfq_packet, packet, self.fingerprint):
			return True
		else:
			return False

	# Check if ICMP packet matches an OS probe
	def is_icmp_os_probe(self, nfq_packet, packet):
		if icmp_detect(nfq_packet, packet, self.fingerprint):
			return True
		else:
			return False


# Instantiate a global instance of this class
inspector = Inspect()
