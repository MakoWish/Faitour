from utils.logger import logger
import utils.config as config
import socket
import threading

class PostgreSQLServer:
	def __init__(self):
		self.running = False
		self.host_ip = config.get_value("network.adapter.ip")
		self.host_port = config.get_service_by_name("postgresql")["port"]
		self.server_socket = None

	# Starts the emulated PostgreSQL server.
	def start(self):
		if self.running:
			logger.debug(f'"type":["info"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"start","reason":"PostgreSQL server emulator is already running","outcome":"success"')
			return

		try:
			logger.info(f'"type":["info"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"start","reason":"PostgreSQL server emulator is starting on {self.host_ip}:{self.host_port}","outcome":"unknown"}},"server":{{"ip":"{self.host_ip}","port":{self.host_port}')
			self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.server_socket.bind((self.host_ip, self.host_port))
			self.server_socket.listen(5)
			self.running = True
			logger.info(f'"type":["start"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"start","reason":"PostgreSQL server emulator has started on {self.host_ip}:{self.host_port}","outcome":"success"}},"server":{{"ip":"{self.host_ip}","port":{self.host_port}')

			threading.Thread(target=self.accept_connections, daemon=True).start()
		except Exception as e:
			logger.error(f'"type":["end"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"start","reason":"PostgreSQL server emulatore failed to start","outcome":"failure"}},"error":{{"message":"{e}"}}')

	# Handles communication with a connected client.
	def handle_client(self, client_socket, address):
		try:
			client_ip = address[0]
			client_port = address[1]

			# Send a PostgreSQL server version string to mimic the real server
			client_socket.send(b"\x52\x00\x00\x00\x0d\x00\x03\x00\x00\x5c\x00\x00\x00\x00")  # Startup Response

			while self.running:
				data = client_socket.recv(1024)
				if not data:
					break

				logger.info(f'"type":["connection","allowed","start"],"kind":"alert","category":["network","intrusion_detection"],"dataset":"faitour.honeypot","action":"handle_client","reason":"Received data {str(data.hex())}","outcome":"success"}},"source":{{"ip":"{client_ip}","port":{client_port}}},"destination":{{"ip":"{self.host_ip}","port":{self.host_port}')

				# Respond with a dummy authentication request (PostgreSQL handshake)
				response = b"R" + b"\x00\x00\x00\x08" + b"\x00\x00\x00\x00"
				client_socket.send(response)

		except Exception as e:
			logger.error(f'"type":["error"],"kind":"event","category":["network"],"dataset":"faitour.application","action":"handle_client","reason":"Error accepting connection","outcome":"failure"}},"error":{{"message":"{e}"}},"source":{{"ip":"{client_ip}","port":{client_port}}},"destination":{{"ip":"{self.host_ip}","port":{self.host_port}')
		finally:
			client_socket.close()

	# Handles incoming client connections.
	def accept_connections(self):
		while self.running:
			try:
				client_socket, address = self.server_socket.accept()
				threading.Thread(target=self.handle_client, args=(client_socket, address), daemon=True).start()
			except Exception as e:
				if self.running:  # Only log errors if the server is running
					logger.error(f'"type":["info"],"kind":"event","category":["network"],"dataset":"faitour.application","action":"accept_connections","reason":"Error accepting connections","outcome":"failure"}},"error":{{"message":"{e}"')

	# Stops the emulated PostgreSQL server.
	def stop(self):
		if not self.running:
			logger.debug(f'"type":["info"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"start","reason":"PostgreSQL server emulator is not running","outcome":"success"')
			return

		self.running = False
		logger.info(f'"type":["info"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"stop","reason":"PostgreSQL server emulator is stopping","outcome":"unknown"}},"server":{{"ip":"{self.host_ip}","port":{self.host_port}')
		if self.server_socket:
			self.server_socket.close()
			self.server_socket = None
		logger.info(f'"type":["end"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"stop","reason":"PostgreSQL server emulator has stopped","outcome":"success"}},"server":{{"ip":"{self.host_ip}","port":{self.host_port}')
