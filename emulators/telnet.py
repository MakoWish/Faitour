import os
import socket
import threading
import subprocess
import utils.config as config
from utils.logger import logger

class TelnetServer:
	def __init__(self):
		self.running = False
		self.host_ip = config.get_value("network.adapter.ip")
		self.host_port = config.get_service_by_name("telnet")["port"]
		self.root_dir = os.path.abspath("./emulators/telnet_root/")
		self.server_socket = None
		self.clients = []

	# Starts the telnet server.
	def start(self):
		if not os.path.exists(self.root_dir):
			logger.error(f'"type":["error"],"kind":"event","category":["process"],"dataset":"application","action":"handle_packet","reason":"Root directory {self.root_dir} does not exist","outcome":"failure"}},"error":{{"message":"Directory does not exist"')
			return

		self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.server_socket.bind((self.host_ip, self.host_port))
		self.server_socket.listen(5)
		self.running = True
		logger.info(f'"type":["info"],"kind":"event","category":["process"],"dataset":"application","action":"handle_packet","reason":"Telnet server started on {self.host_ip}:{self.host_port}","outcome":"success"')

		while self.running:
			try:
				client_socket, address = self.server_socket.accept()
				client_ip = address[0]
				client_port = address[1]
				logger.info(f'"type":["connection","allowed","start"],"kind":"alert","category":["network","intrusion_detection"],"dataset":"honeypot","action":"start","reason":"New connection from","outcome":"success"}},"source":{{"ip":"{client_ip}","port":{client_port}}},"destination":{{"ip":"{self.host_ip}","port":{self.host_port}')
				client_thread = threading.Thread(target=self.handle_client, args=(client_socket, address))
				client_thread.start()
				self.clients.append((client_socket, client_thread))
			except Exception as e:
				logger.error(f'"type":["error"],"kind":"event","category":["process"],"dataset":"application","action":"handle_packet","reason":"Server error","outcome":"failure"}},"error":{{"message":"{e}"')

	# Prompt for username
	def get_username(self, client_socket):
		client_socket.send(b"Username: ")
		client_socket.recv(1024)   # Disregard the automated `&& !"'` control character response from the client
		username = client_socket.recv(1024).decode(errors='ignore').strip()
		return username

	# Prompt for password
	def get_password(self, client_socket):
		client_socket.send(b"Password: ")
		password = client_socket.recv(1024).decode(errors='ignore').strip()
		return password

	# Handle client interaction
	def handle_client(self, client_socket, address):
		# Get username and password from config
		username = self.get_username(client_socket)
		password = self.get_password(client_socket)
		client_ip = address[0]
		client_port = address[1]

		# Check if credentials are valid based on config
		if username == config.get_service_by_name("telnet")["username"] and password == config.get_service_by_name("telnet")["password"]:
			print(f"{username} user has logged in")
			logger.info(f'"type":["user","connection","allowed","start"],"kind":"alert","category":["authentication","network","intrusion_detection"],"dataset":"honeypot","action":"handle_client","reason":"User logged in","outcome":"success"}},"source":{{"ip":"{client_ip}","port":{client_port}}},"destination":{{"ip":"{self.host_ip}","port":{self.host_port}}},"user":{{"name":"{username}","password":"{password}"')
		elif username == "anonymous" and config.get_service_by_name("telnet")["allow_anonymous"]:
			logger.info(f'"type":["user","connection","allowed","start"],"kind":"alert","category":["authentication","network","intrusion_detection"],"dataset":"honeypot","action":"handle_client","reason":"User logged in","outcome":"success"}},"source":{{"ip":"{client_ip}","port":{client_port}}},"destination":{{"ip":"{self.host_ip}","port":{self.host_port}}},"user":{{"name":"{username}","password":"{password}"')
		else:
			client_socket.send(b"Invalid login!\n")
			client_socket.close
			return None

		# Handles interactions with the connected telnet client.
		client_socket.send(config.get_service_by_name("telnet")["banner"].encode("utf-8"))
		current_dir = self.root_dir

		try:
			while True:
				# Send prompt
				client_socket.send(f"{os.path.basename(current_dir)}> ".encode())
				data = client_socket.recv(1024)

				# Handle Telnet negotiation commands (starting with 0xFF)
				if not data:
					break

				# Ignore Telnet negotiation sequences
				if data[0] == 0xff:
					continue

				data = data.decode(errors='ignore').strip()

				if data.lower() in ["exit", "quit"]:
					client_socket.send(b"Goodbye!\n")
					break

				# Handle shell-like commands
				if data.startswith("cd "):
					path = data[3:].strip()
					new_dir = os.path.abspath(os.path.join(current_dir, path))
					# Ensure the directory is within the root_dir
					if os.path.commonpath([self.root_dir, new_dir]) == self.root_dir and os.path.exists(new_dir) and os.path.isdir(new_dir):
						current_dir = new_dir
						logger.info(f'"type":["user","access","allowed"],"kind":"alert","category":["file","intrusion_detection"],"dataset":"honeypot","action":"handle_client","reason":"User access to {new_dir} granted","outcome":"success"}},"source":{{"ip":"{client_ip}","port":{client_port}}},"destination":{{"ip":"{self.host_ip}","port":{self.host_port}}},"user":{{"name":"{username}","password":"{password}"}},"file":{{"directory":"{new_dir}"')
					else:
						client_socket.send(b"Directory not found or access denied.\n")
						logger.error(f'"type":["user","access","denied"],"kind":"alert","category":["file","intrusion_detection"],"dataset":"honeypot","action":"handle_client","reason":"User access to {new_dir} denied","outcome":"failure"}},"source":{{"ip":"{client_ip}","port":{client_port}}},"destination":{{"ip":"{self.host_ip}","port":{self.host_port}}},"user":{{"name":"{username}","password":"{password}"}},"file":{{"directory":"{new_dir}"')
				elif data == "ls":
					try:
						files = os.listdir(current_dir)
						response = "\n".join(files) + "\n"
						client_socket.send(response.encode())
						logger.info(f'"type":["user","access","allowed"],"kind":"alert","category":["file","intrusion_detection"],"dataset":"honeypot","action":"handle_client","reason":"User listed directory {current_dir}","outcome":"success"}},"source":{{"ip":"{client_ip}","port":{client_port}}},"destination":{{"ip":"{self.host_ip}","port":{self.host_port}}},"user":{{"name":"{username}","password":"{password}"}},"file":{{"directory":"{current_dir}"')
					except Exception as e:
						client_socket.send(f"Error listing directory: {e}\n".encode())
						logger.error(f'"type":["user","access","denied"],"kind":"alert","category":["file","intrusion_detection"],"dataset":"honeypot","action":"handle_client","reason":"User attempt to list directory {current_dir} failed","outcome":"failure"}},"source":{{"ip":"{client_ip}","port":{client_port}}},"destination":{{"ip":"{self.host_ip}","port":{self.host_port}}},"user":{{"name":"{username}","password":"{password}"}},"error":{{"message":"{e}"}},"file":{{"directory":"{current_dir}"')
				elif data.startswith("cat "):
					filename = data[4:].strip()
					filepath = os.path.abspath(os.path.join(current_dir, filename))
					# Ensure the file is within the root_dir
					if os.path.commonpath([self.root_dir, filepath]) == self.root_dir and os.path.exists(filepath) and os.path.isfile(filepath):
						with open(filepath, 'r') as f:
							client_socket.send(f.read().encode())
							client_socket.send(b'\r\n')
							logger.info(f'"type":["user","access","allowed"],"kind":"alert","category":["file","intrusion_detection"],"dataset":"honeypot","action":"handle_client","reason":"User cat\'ed contents of file {filepath}","outcome":"success"}},"source":{{"ip":"{client_ip}","port":{client_port}}},"destination":{{"ip":"{self.host_ip}","port":{self.host_port}}},"user":{{"name":"{username}","password":"{password}"}},"file":{{"name":"{filename}","directory":"{filepath}"')
					else:
						client_socket.send(b"File not found or access denied.\n")
						logger.error(f'"type":["user","access","denied"],"kind":"alert","category":["file","intrusion_detection"],"dataset":"honeypot","action":"handle_client","reason":"User attempt to cat file {filepath} failed","outcome":"failure"}},"source":{{"ip":"{client_ip}","port":{client_port}}},"destination":{{"ip":"{self.host_ip}","port":{self.host_port}}},"user":{{"name":"{username}","password":"{password}"}},"error":{{"message":"File not found or access denied"')
				else:
					try:
						result = subprocess.check_output(data, shell=True, cwd=current_dir, stderr=subprocess.STDOUT)
						client_socket.send(result)
						logger.info(f'"type":["user","access","allowed"],"kind":"alert","category":["file","intrusion_detection"],"dataset":"honeypot","action":"handle_client","reason":"User ran unhandled command {data}","outcome":"success"}},"source":{{"ip":"{client_ip}","port":{client_port}}},"destination":{{"ip":"{self.host_ip}","port":{self.host_port}}},"user":{{"name":"{username}","password":"{password}"')
					except subprocess.CalledProcessError as e:
						client_socket.send(e.output or b"Command failed.\n")
						logger.error(f'"type":["user","access","denied"],"kind":"alert","category":["file","intrusion_detection"],"dataset":"honeypot","action":"handle_client","reason":"User command {data} failed","outcome":"failure"}},"source":{{"ip":"{client_ip}","port":{client_port}}},"destination":{{"ip":"{self.host_ip}","port":{self.host_port}}},"user":{{"name":"{username}","password":"{password}"}},"error":{{"message":"{e}"')
		except Exception as e:
			logger.error(f'"type":["error"],"kind":"event","category":["process"],"dataset":"application","action":"handle_client","reason":"Client error","outcome":"failure"}},"error":{{"message":"{e}"')
		finally:
			client_socket.close()

	# Stops the telnet server.
	def stop(self):
		logger.info(f'"type":["end"],"kind":"event","category":["process"],"dataset":"application","action":"stop","reason":"Telnet server emulator is stopping","outcome":"success"')
		self.running = False
		if self.server_socket:
			self.server_socket.close()
		for client_socket, _ in self.clients:
			client_socket.close()
		for _, client_thread in self.clients:
			client_thread.join()

		# Clear the list of clients
		self.clients = []
		logger.info(f'"type":["end"],"kind":"event","category":["process"],"dataset":"application","action":"stop","reason":"Telnet server emulator has stopped","outcome":"success"')
