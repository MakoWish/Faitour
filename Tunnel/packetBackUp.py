from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, UDP, ICMP, ARP, Ether, Raw
from Tunnel.VirtualDevice import destroyTap, getVirtualDevices
from Cloaked.probe.ecn_check import ecn_detect
from Cloaked.probe.seqgen_check import seqgen_detect
from Cloaked.probe.T2toT7_check import t2tot7_detect
from Cloaked.probe.icmp_check import icmp_detect
from Cloaked.probe.udp_check import udp_detect
from Cloaked.probe.service_check import service_detect
import gconstant as gc
import time
import sys
from subprocess import DEVNULL, STDOUT, check_call
import socket
import json
import base64
import asyncio


def handle_packet(nfq_packet):
	try:
		pkt = IP(nfq_packet.get_payload())
		payload = str(base64.encodebytes(nfq_packet.get_payload()).decode('ascii'))
		gc.LOGGER.debug('Got payload for packet: ' + payload[:15])
	except:
		gc.LOGGER.error('Failed to get packet payload: ' + payload[:15])
		forward_packet(nfq_packet)
		return 0

	try:
		if pkt[IP].dst == '127.0.0.1':
			gc.LOGGER.debug('Forwarding packet destined for localhost: ' + payload[:15])
			forward_packet(nfq_packet)
			return 0

		virtDevices = getVirtualDevices()  # Get Dict of virtual devices
		if pkt[IP].dst in virtDevices.keys():  # Check if the Packet is intended for any of the virtual devices
			fgrpt = virtDevices[pkt[IP].dst].cfg.fgrpt  # Get the OS Fingerprint of the virtual device
			mac = virtDevices[pkt[IP].dst].macAddr  # Get the MAC Address of the Virtual Device
			services = virtDevices[pkt[IP].dst].cfg.service  # Get the Services of the virtual device
			device_name = virtDevices[pkt[IP].dst].name  # Get the Name of the virtual device

			if pkt.haslayer(TCP):
				port = pkt[TCP].dport
				if not (seqgen_detect(nfq_packet, pkt, fgrpt, mac, gc.SOCKET_INTERFACE) or
						ecn_detect(nfq_packet, pkt, fgrpt, mac, gc.SOCKET_INTERFACE) or
						t2tot7_detect(nfq_packet, pkt, fgrpt, mac, gc.SOCKET_INTERFACE) or
						service_detect(nfq_packet, pkt, fgrpt, mac, services, gc.SOCKET_INTERFACE)):
					gc.LOGGER.debug('TCP packet with destination port ' + str(port) + ' does not match a fingerprint. Forwarding...')
					forward_packet(nfq_packet)
				else:
					gc.LOGGER.debug('TCP packet with destination port ' + str(port) + ' matches a fingerprint.')
			elif pkt.haslayer(UDP):
				port = pkt[UDP].dport
				if not udp_detect(nfq_packet, pkt, fgrpt, mac, gc.SOCKET_INTERFACE):
					gc.LOGGER.debug('UDP packet with destination port ' + str(port) + ' does not match a fingerprint. Forwarding...')
					forward_packet(nfq_packet)
				else:
					gc.LOGGER.debug('UDP packet with destination port ' + str(port) + ' matches a fingerprint.')
			elif pkt.haslayer(ICMP):
				port = 0
				if not icmp_detect(nfq_packet, pkt, fgrpt, mac, gc.SOCKET_INTERFACE):
					gc.LOGGER.debug('ICMP packet does not match a fingerprint. Forwarding...')
					forward_packet(nfq_packet)
				else:
					gc.LOGGER.debug('ICMP packet matches a fingerprint.')
			else:
				port = 0
				gc.LOGGER.debug('Unknown protocol. Setting port to 0 and forwarding...')
				forward_packet(nfq_packet)

			try:
				parse_data = base64.encodebytes(nfq_packet.get_payload()).decode('ascii')
				data = {'timestamp': time.time(), 'dst_ip': pkt[IP].dst, 'host_os': device_name, 'src_ip': pkt[IP].src, 'services': port, 'packet': parse_data}
				gc.PACKET_LOGGER.info(json.dumps(data))
			except Exception as e:
				gc.LOGGER.error('Error parsing encoded bytes: ' + str(e))

		else:
			gc.LOGGER.debug('Packet destination does not match virtual device. Forwarding...')
			forward_packet(nfq_packet)  # If packet not intended for the virtual devices, then forward it
			return 0

	except Exception as e:
		gc.LOGGER.error('Unable to retrieve packet details: ' + str(e))

	return 0


def flush_tables():
	#  Flush IP tables after exiting program
	check_call(['iptables', '-D', 'INPUT', '-j', 'NFQUEUE', '--queue-num', '2'], stdout=DEVNULL, stderr=STDOUT)


def forward_packet(nfq_packet):
	#  Send the packet from NFQUEUE without modification
	try:
		nfq_packet.accept()
		payload = str(base64.encodebytes(nfq_packet.get_payload()).decode('ascii'))
		gc.LOGGER.debug('Accepted packet: ' + payload[:15])
	except:
		gc.LOGGER.warn('Failed to accept packet: ' + base64.encodebytes(nfq_packet.get_payload()).decode('ascii'))
		nfq_packet.drop()


def drop_packet(nfq_packet):
	# Drop the packet from NFQUEUE
	nfq_packet.drop()
	gc.LOGGER.debug('Dropped packet: ' + base64.encodebytes(nfq_packet.get_payload()).decode('ascii'))


def rules():
	#  Rules to be added to IP tables
	gc.LOGGER.info('Setting iptables rule "arp_ignore=1"')
	check_call(['sysctl', 'net.ipv4.conf.all.arp_ignore=1'], stdout=DEVNULL, stderr=STDOUT)
	gc.LOGGER.info('Setting iptables rule "arp_announce=2"')
	check_call(['sysctl', 'net.ipv4.conf.all.arp_announce=2'], stdout=DEVNULL, stderr=STDOUT)
	gc.LOGGER.info('Setting iptables rule "rp_filter=2"')
	check_call(['sysctl', 'net.ipv4.conf.all.rp_filter=2'], stdout=DEVNULL, stderr=STDOUT)
	gc.LOGGER.info('Setting iptables rule "ip_forward"')
	check_call(['echo 1 | tee /proc/sys/net/ipv4/ip_forward'], stdout=DEVNULL, stderr=STDOUT, shell=True)
	gc.LOGGER.info('Adding NFQUEUE to iptables"')
	check_call(['iptables', '-I', 'INPUT', '-j', 'NFQUEUE', '--queue-num', '2'], stdout=DEVNULL, stderr=STDOUT)


async def monitor_nfqueue_queue_size(interval=1):
	"""
	Monitors the queue size of nfqueue by reading the third column
	of /proc/net/netfilter/nfnetlink_queue. Runs asynchronously at the specified interval.
	If the queue size exceeds 1024 packets, it will re-bind the NFQUEUE.
	"""
	while True:
		try:
			with open('/proc/net/netfilter/nfnetlink_queue', 'r') as f:
				# Read the single line containing queue stats
				line = f.readline().strip()
				if line:
					columns = line.split()
					if len(columns) > 2:
						queue_size = int(columns[2])  # Third column is the queue size
						gc.LOGGER.debug(f"NFQUEUE current queue size: {queue_size}")

						# If the queue size exceeds the threshold (1024), re-bind the queue
						if queue_size > 1024:
							gc.LOGGER.warn(f"NFQUEUE queue size exceeds threshold (1024): {queue_size}. Re-binding the queue.")

							# Unbind and re-bind the NFQUEUE
							nfqueue.unbind()
							nfqueue.bind(2, handle_packet, max_len=10240)
							gc.LOGGER.info("NFQUEUE re-bound due to queue size exceeding threshold.")

					else:
						gc.LOGGER.warn("Unexpected format in /proc/net/netfilter/nfnetlink_queue")
				else:
					gc.LOGGER.warn("/proc/net/netfilter/nfnetlink_queue is empty or unreadable.")
		except FileNotFoundError:
			gc.LOGGER.error("/proc/net/netfilter/nfnetlink_queue not found. Is nfqueue configured properly?")
		except Exception as e:
			gc.LOGGER.error(f"Error monitoring NFQUEUE queue size: {e}")
		
		# Wait for the specified interval before checking again
		await asyncio.sleep(interval)


def startIntercept():
	rules()
	nfqueue = NetfilterQueue()
	# Bind it to queue number 2
	nfqueue.bind(2, handle_packet, max_len=10240)
	s = socket.fromfd(nfqueue.get_fd(), socket.AF_INET, socket.SOCK_STREAM)

	loop = asyncio.get_event_loop()

	try:
		# Schedule the queue size monitoring task
		monitor_task = loop.create_task(monitor_nfqueue_queue_size(interval=2))

		# Run the main nfqueue socket in the asyncio event loop
		gc.LOGGER.info('Starting NFQUEUE socket')
		loop.run_in_executor(None, nfqueue.run_socket, s)
		loop.run_forever()

	except KeyboardInterrupt:
		gc.LOGGER.info('Attempting to cleanly shutdown Faitour due to keyboard interrupt')
	except Exception as e:
		gc.LOGGER.error(f"Exception caught: {e}")
		gc.LOGGER.error('Attempting to cleanly shutdown Faitour due to unknown exception')

	finally:
		# Clean up resources
		gc.LOGGER.info('Flushing iptables')
		flush_tables()
		gc.LOGGER.info('Unbind NFQUEUE')
		nfqueue.unbind()
		gc.LOGGER.info('Destroying virtual interface')
		destroyTap()

		# Cancel the monitoring task if it is running
		if monitor_task:
			gc.LOGGER.info("Cancelling monitor task")
			monitor_task.cancel()
			try:
				loop.run_until_complete(monitor_task)
			except asyncio.CancelledError:
				gc.LOGGER.info("Monitor task cancelled")

		# Stop the asyncio event loop
		loop.stop()
		loop.close()

		gc.LOGGER.info('Faitour has been stopped.')
		os._exit()

