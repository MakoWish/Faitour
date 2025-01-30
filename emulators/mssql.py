from utils.logger import logger
import utils.config as config
import socket
import threading

class MSSQLEmulator:
	def __init__(self):
		self.running = False
		self.host_ip = config.get_value("network.adapter.ip")
		self.host_port = config.get_service_by_name("mssql")["port"]
		self.server_socket = None

	# Start the MSSQL emulator server.
	def start(self):
		logger.info(f'"type":["start"],"kind":"event","category":["process"],"dataset":"application","action":"start_mssql","reason":"MSSQL server emulator is starting on {self.host_ip}:{self.host_port}","outcome":"success"')
		self.running = True
		self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.server_socket.bind((self.host_ip, self.host_port))
		self.server_socket.listen(5)

		while True:
			client_socket, addr = self.server_socket.accept()
			client_ip = addr[0]
			client_port = addr[1]
			logger.info(f'"type":["connection","allowed","start"],"kind":"alert","category":["network","intrusion_detection"],"dataset":"honeypot","action":"server_socket.accept","reason":"MSSQL client connection established","outcome":"success"}},"source":{{"ip":"{client_ip}","port":{client_port}}},"destination":{{"ip":"{self.host_ip}","port":{self.host_port}')
			threading.Thread(target=self.handle_client, args=(client_socket, addr)).start()

	# Handle client interactions.
	def handle_client(self, client_socket, addr):
		try:
			client_ip = addr[0]
			client_port = addr[1]

			# Send a fake MSSQL Server response header (resembles TDS protocol)
			client_socket.sendall(self.generate_mssql_banner())

			# Receive data from the client
			data = client_socket.recv(1024)
			logger.debug(f'"type":["connection","allowed","start"],"kind":"alert","category":["network","intrusion_detection"],"dataset":"honeypot","action":"handle_client","reason":"MSSQL received data","outcome":"success"}},"source":{{"ip":"{client_ip}","port":{client_port}}},"destination":{{"ip":"{self.host_ip}","port":{self.host_port}')

			# Respond to any received data with a generic error or acknowledgment
			if data:
				response = b"\x04\x01\x00\x25\x00\x00\x01\x00Login failed for user 'sa'.\x00\x00"
				client_socket.sendall(response)
		except Exception as e:
			logger.error(f'"type":["error"],"kind":"event","category":["process"],"dataset":"application","action":"handle_client","reason":"MSSQL server emulator error","outcome":"failure"}},"error":{{"message":"{e}"')
		finally:
			client_socket.close()

	# Generate a banner that resembles an MSSQL server.
	def generate_mssql_banner(self):
		# Fake MSSQL response (e.g., login packet header)
		header = config.get_service_by_name("mssql")["fingerprint"].strip()
		return header.encode('utf-8')

	# Stop the server.
	def stop(self):
		if self.server_socket:
			logger.info(f'"type":["end"],"kind":"event","category":["process"],"dataset":"application","action":"stop_servers","reason":"MSSQL server eumlator is stopping","outcome":"success"')
			self.server_socket.close()
			self.running = False
			logger.info(f'"type":["end"],"kind":"event","category":["process"],"dataset":"application","action":"stop_servers","reason":"MSSQL server emulator has stopped","outcome":"success"')
