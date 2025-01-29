from utils.logger import logger
import utils.config as config
import socket
import threading

class MySQLEmulator:
	def __init__(self):
		self.running = False
		self.host_ip = config.get_value("network.adapter.ip")
		self.host_port = config.get_service_by_name("mysql")["port"]
		self.server_socket = None

	# Start the MySQL emulator server.
	def start(self):
		self.running = True
		logger.info(f'"type":["start"],"kind":"event","category":["process"],"dataset":"application","action":"start","reason":"MySQL server emulator is starting on {self.host_ip}:{self.host_port}","outcome":"success"')
		self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.server_socket.bind((self.host_ip, self.host_port))
		self.server_socket.listen(5)

		while True:
			client_socket, addr = self.server_socket.accept()
			client_ip = addr[0]
			client_port = addr[1]
			logger.info(f'"type":["connection","allowed","start"],"kind":"alert","category":["network","intrusion_detection"],"dataset":"honeypot","action":"server_socket.accept","reason":"MySQL connection established","outcome":"success"}},"source":{{"ip":"{client_ip}","port":{client_port}}},"destination":{{"ip":"{self.host_ip}","port":{self.host_port}')
			threading.Thread(target=self.handle_client, args=(client_socket,)).start()

	# Handle client interactions.
	def handle_client(self, client_socket):
		try:
			# Send a fake MySQL handshake packet
			client_socket.sendall(self.generate_mysql_handshake())

			# Receive data from the client
			data = client_socket.recv(1024)
			logger.debug(f'"type":["connection","allowed","start"],"kind":"alert","category":["network","intrusion_detection"],"dataset":"honeypot","action":"handle_client","reason":"MySQL received data","outcome":"success"')

			# Respond to any received data with a generic error or acknowledgment
			if data:
				response = b"\xff\x15\x04Access denied for user 'root'@'localhost' (using password: YES)\x00"
				client_socket.sendall(response)
		except Exception as e:
			logger.error(f'"type":["error"],"kind":"event","category":["process"],"dataset":"application","action":"handle_client","reason":"MySQL server emulator error","outcome":"failure"}},"error":{{"message":"{e}"')
		finally:
			client_socket.close()

	 # Generate a handshake packet that resembles a MySQL server.
	def generate_mysql_handshake(self):
		# Fake MySQL handshake packet (protocol version, server version, thread ID, etc.)
		header = config.get_service_by_name("mysql")["fingerprint"].strip()
		return header.encode('utf-8')

	# Stop the server.
	def stop(self):
		if self.server_socket:
			logger.info(f'"type":["end"],"kind":"event","category":["process"],"dataset":"application","action":"stop","reason":"MySQL server emulator is stopping","outcome":"success"')
			self.server_socket.close()
			self.running = False
			logger.info(f'"type":["end"],"kind":"event","category":["process"],"dataset":"application","action":"stop","reason":"MySQL server emulator has stopped","outcome":"success"')
