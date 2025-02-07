import codecs
import socket
import threading
from utils.logger import logger
import utils.config as config

class RPCEmulator:
	def __init__(self):
		self.running = False
		self.host_ip = config.get_value("network.adapter.ip")
		self.host_port = config.get_service_by_name("rpc")["port"]
		self.server_socket = None

	# Start the RPC emulator server.
	def start(self):
		if self.running:
			logger.debug(f'"type":["info"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"start","reason":"RPC server emulator is already running","outcome":"success"')
			return

		logger.info(f'"type":["info"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"start","reason":"RPC server emulator is starting on {self.host_ip}:{self.host_port}","outcome":"unknown"}},"server":{{"ip":"{self.host_ip}","port":{self.host_port}')
		self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Enable port reuse
		self.server_socket.bind((self.host_ip, self.host_port))
		self.server_socket.listen(5)
		self.running = True
		logger.info(f'"type":["start"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"start","reason":"RPC server emulator has started on {self.host_ip}:{self.host_port}","outcome":"success"}},"server":{{"ip":"{self.host_ip}","port":{self.host_port}')

		while True:
			client_socket, address = self.server_socket.accept()
			threading.Thread(target=self.handle_client, args=(client_socket, address)).start()

	# Handle client interactions.
	def handle_client(self, client_socket, address):
		try:
			client_ip = address[0]
			client_port = address[1]

			# If initial data does not start with 0xFF, this is likely an NMAP service fingerprinting scan
			data = client_socket.recv(1024)
			if not data or data[0] != 0xff:
				logger.warning(f'"type":["connection","start"],"kind":"event","category":["network","intrusion_detection"],"dataset":"honeypot","action":"handle_client","reason":"Initial client data appears to be RPC service fingerprinting attempt","outcome":"unknown"}},"source":{{"ip":"{client_ip}","port":{client_port}}},"destination":{{"ip":"{self.host_ip}","port":{self.host_port}')

				# Send out spoofed fingerprint
				binary_fingerprint = codecs.decode(config.get_service_by_name("rpc")["fingerprint"], "unicode_escape").encode("latin1")
				client_socket.sendall(binary_fingerprint)

			logger.info(f'"type":["connection","allowed","start"],"kind":"alert","category":["network","intrusion_detection"],"dataset":"faitour.honeypot","action":"handle_client","reason":"RPC received data","outcome":"success"}},"source":{{"ip":"{client_ip}","port":{client_port}}},"destination":{{"ip":"{self.host_ip}","port":{self.host_port}')

			# Respond to any received data with a generic error or acknowledgment
			if data:
				response = b"\xff\x15\x04Access denied for user 'root'@'localhost' (using password: YES)\x00"
				client_socket.sendall(response)
		except Exception as e:
			logger.error(f'"type":["end"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"handle_client","reason":"RPC server emulator error","outcome":"failure"}},"error":{{"message":"{e}"')
		finally:
			client_socket.close()

	# Stop the server.
	def stop(self):
		if not self.running:
			logger.debug(f'"type":["info"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"start","reason":"RPC server emulator is not running","outcome":"success"')
			return

		if self.server_socket:
			logger.info(f'"type":["info"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"stop","reason":"RPC server emulator is stopping","outcome":"unknown"}},"server":{{"ip":"{self.host_ip}","port":{self.host_port}')
			self.server_socket.close()
			self.running = False
			logger.info(f'"type":["end"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"stop","reason":"RPC server emulator has stopped","outcome":"success"}},"server":{{"ip":"{self.host_ip}","port":{self.host_port}')
