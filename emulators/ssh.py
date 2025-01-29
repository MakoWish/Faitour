import os
import threading
import traceback
import utils.config as config
from utils.logger import logger
from paramiko import ServerInterface, Transport, AUTH_SUCCESSFUL, OPEN_SUCCEEDED, SFTPServer
from paramiko.sftp_server import SFTPServerInterface, SFTPAttributes
from paramiko import RSAKey
from socket import socket, AF_INET, SOCK_STREAM
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

class SimpleSSHServer(ServerInterface):
	USERNAME = config.get_service_by_name("ssh")["username"]
	PASSWORD = config.get_service_by_name("ssh")["password"]
	ROOT_DIR = os.path.abspath("./emulators/ssh_root")

	def __init__(self):
		self.event = threading.Event()

	def check_auth_password(self, username, password):
		if username == self.USERNAME and password == self.PASSWORD:
			logger.info(f'"type":["connection","allowed","start"],"kind":"alert","category":["network","intrusion_detection"],"dataset":"honeypot","action":"check_auth_password","reason":"SSH authentication successful","outcome":"success"}},"user":{{"name":"{username}","password":"{password}"')
			return AUTH_SUCCESSFUL
		logger.warning(f'"type":["connection","denied"],"kind":"alert","category":["network","intrusion_detection"],"dataset":"honeypot","action":"check_auth_password","reason":"SSH authentication failed","outcome":"failure"}},"user":{{"name":"{username}","password":"{password}"')
		return None

	def check_channel_request(self, kind, chanid):
		if kind == "session":
			return OPEN_SUCCEEDED
		return None

	def get_allowed_auths(self, username):
		return "password"

	def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
		client_ip, client_port = channel.getpeername()
		logger.info(f'"type":["connection","allowed","start"],"kind":"alert","category":["network","intrusion_detection"],"dataset":"honeypot","action":"check_channel_pty_request","reason":"SSH PTY requested","outcome":"success"}},"source":{{"ip":"{client_ip}","port":{client_port}')
		return True

	def check_channel_shell_request(self, channel):
		client_ip, client_port = channel.getpeername()
		logger.info(f'"type":["connection","allowed","start"],"kind":"alert","category":["network","intrusion_detection"],"dataset":"honeypot","action":"check_channel_shell_request","reason":"SSH shell requested","outcome":"success"}},"source":{{"ip":"{client_ip}","port":{client_port}')
		self.event.set()
		return True

	def check_channel_subsystem_request(self, channel, name):
		if name == "sftp":
			client_ip, client_port = channel.getpeername()
			logger.info(f'"type":["connection","allowed","start"],"kind":"alert","category":["network","intrusion_detection"],"dataset":"honeypot","action":"check_channel_subsystem_request","reason":"SFTP subsystem requested","outcome":"success"}},"source":{{"ip":"{client_ip}","port":{client_port}')
			return True
		return False

	def open_sftp_server(self, channel):
		client_ip, client_port = channel.getpeername()
		logger.info(f'"type":["connection","allowed","start"],"kind":"alert","category":["network","intrusion_detection"],"dataset":"honeypot","action":"open_sftp_server","reason":"SFTP server opening","outcome":"success"}},"source":{{"ip":"{client_ip}","port":{client_port}')
		return SimpleSFTPServer(channel)

class SimpleSFTPServer(SFTPServer):
	def __init__(self, channel):
		super().__init__(channel)

	def _realpath(self, path):
		real_path = os.path.abspath(os.path.join(SimpleSSHServer.ROOT_DIR, path.lstrip("/")))
		if not real_path.startswith(SimpleSSHServer.ROOT_DIR):
			logger.warning(f'"type":["connection","denied"],"kind":"event","category":["process"],"dataset":"application","action":"_realpath","reason":"Access denied to path: {path}","outcome":"success"')
		return real_path

	def list_folder(self, path):
		real_path = self._realpath(path)
		try:
			files = os.listdir(real_path)
			attributes = []
			for file in files:
				file_path = os.path.join(real_path, file)
				stats = os.stat(file_path)
				attributes.append(SFTPAttributes.from_stat(stats, file))
			return attributes
		except Exception as e:
			logger.error(f'"type":["error"],"kind":"event","category":["process"],"dataset":"application","action":"list_folder","reason":"Error listing folder {path}","outcome":"failure"}},"error":{{"message":"{e}"')
			raise

	def stat(self, path):
		try:
			real_path = self._realpath(path)
			stats = os.stat(real_path)
			return SFTPAttributes.from_stat(stats)
		except Exception as e:
			logger.error(f'"type":["error"],"kind":"event","category":["process"],"dataset":"application","action":"stat","reason":"Error stat\'ing path {path}","outcome":"failure"}},"error":{{"message":"{e}"')
			raise

	def open(self, path, flags, attr):
		try:
			real_path = self._realpath(path)
			mode = {os.O_RDONLY: "rb", os.O_WRONLY: "wb"}.get(flags & (os.O_RDONLY | os.O_WRONLY))
			return open(real_path, mode)
		except Exception as e:
			logger.error(f'"type":["error"],"kind":"event","category":["process"],"dataset":"application","action":"open","reason":"ErrorError opening file {path}","outcome":"failure"}},"error":{{"message":"{e}"')
			raise

class SSHServer:
	def __init__(self):
		self.running = False
		self.host_ip = config.get_value("network.adapter.ip")
		self.host_port = config.get_service_by_name("ssh")["port"]
		self.server_socket = None
		self.transport = None
		self.thread = None

	def start(self):
		if self.thread is not None and self.thread.is_alive():
			self.running = True
			return

		self.host_key = self.get_ssh_key()
		self.thread = threading.Thread(target=self._run_server)
		self.thread.start()
		self.running = True

	def _run_server(self):
		logger.info(f'"type":["start"],"kind":"event","category":["process"],"dataset":"application","action":"_run_server","reason":"SNMP server emulator is starting on {self.host_ip}:{self.host_port}","outcome":"success"')
		self.server_socket = socket(AF_INET, SOCK_STREAM)
		self.server_socket.bind((self.host_ip, self.host_port))
		self.server_socket.listen(100)
		self.server_socket.settimeout(1)  # Set a timeout to avoid blocking indefinitely

		while self.running:
			try:
				client_socket, client_address = self.server_socket.accept()
				client_ip = client_address[0]
				client_port = client_address[1]
				logger.info(f'"type":["connection","allowed","start"],"kind":"alert","category":["network","intrusion_detection"],"dataset":"honeypot","action":"_run_server","reason":"SSH server accepted connection","outcome":"success"}},"source":{{"ip":"{client_ip}","port":{client_port}}},"destination":{{"ip":"{self.host_ip}","port":{self.host_port}')

				self.transport = Transport(client_socket)
				self.transport.add_server_key(self.host_key)
				server = SimpleSSHServer()
				self.transport.start_server(server=server)
				channel = self.transport.accept()
				if channel is None:
					continue

				server.event.wait(10)
				if not server.event.is_set():
					logger.warning("SSH no shell request received, closing channel")
					logger.warning(f'"type":["error"],"kind":"event","category":["process"],"dataset":"application","action":"_run_server","reason":"SSH no shell request received, closing channel","outcome":"failure"')
					channel.close()
					continue

				self._handle_shell(channel)
			except Exception as e:
				if isinstance(e, OSError) and not self.running:
					# Stop gracefully after closing socket
					break

	def _handle_shell(self, channel):
		try:
			client_ip, client_port = channel.getpeername()
			logger.info(f'"type":["connection","allowed","start"],"kind":"alert","category":["network","intrusion_detection"],"dataset":"honeypot","action":"_handle_shell","reason":"SSH connection","outcome":"success"}},"source":{{"ip":"{client_ip}","port":{client_port}}},"destination":{{"ip":"{self.host_ip}","port":{self.host_port}')
			channel.send("**********************************\r\n")
			channel.send("This is a private server!\r\n")
			channel.send("Unauthorized access is prohibited!\r\n")
			channel.send("**********************************\r\n")
			buffer = ""
			channel.send("admin@hrrecords:$ ")  # Send initial prompt
			while True:
				data = channel.recv(1024).decode("utf-8")
				if not data:
					break

				for char in data:
					if char in ['\r', '\n']:
						command = buffer.strip()
						buffer = ""

						logger.info(f"SSH client {client_ip}: {command}")
						logger.info(f'"type":["connection","allowed","start"],"kind":"alert","category":["network","intrusion_detection"],"dataset":"honeypot","action":"_handle_shell","reason":"SSH client: {command}","outcome":"success"}},"source":{{"ip":"{client_ip}","port":{client_port}}},"destination":{{"ip":"{self.host_ip}","port":{self.host_port}')
						if command.lower() in ["exit", "quit"]:
							channel.send("\r\nGoodbye!")
							return
						elif command:
							try:
								# Change directory to ROOT_DIR to ensure isolation
								os.chdir(f"{SimpleSSHServer.ROOT_DIR}/home/admin")
								#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!#
								# This will need some work to remain even somewhat
								# secure. Let's only allow a couple commands for now
								#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!#
								#if command in ["ls", "ls -l", "cat notes.txt"]:
								#	import subprocess

								#	process = subprocess.Popen(
								#		command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
								#	)
								#	stdout, stderr = process.communicate()
								#	if stdout:
								#		channel.send(f"\r\n{stdout.strip()}")
								#	if stderr:
								#		channel.send(f"\r\n{stderr.strip()}")
								#else:
								#	channel.send("\r\nAccess denied! Please contact HR for assistance!")
								if command.startswith("cd "):
									 
									new_dir = command[3:]
									new_path = os.path.abspath(os.path.join(SimpleSSHServer.ROOT_DIR, new_dir))
									if new_path.startswith(SimpleSSHServer.ROOT_DIR):
										os.chdir(new_path)
										channel.send("\r\n")
									else:
										channel.send("\r\nAccess denied")
								elif command == "pwd":
									relative_path = os.path.relpath(os.getcwd(), SimpleSSHServer.ROOT_DIR)
									channel.send(f"\r\n/{relative_path if relative_path != '.' else ''}")
								else:
									import subprocess

									process = subprocess.Popen(
										command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
									)
									stdout, stderr = process.communicate()
									if stdout:
										channel.send(f"\r\n{stdout.strip()}")
									if stderr:
										channel.send(f"\r\n{stderr.strip()}")
							except Exception as e:
								channel.send(f"\r\nError executing command: {e}")
						channel.send("\r\nadmin@hrrecords:$ ")  # Send prompt after processing command
					else:
						buffer += char
						channel.send(char)  # Echo back typed character
		except Exception as e:
			logger.error(f'"type":["error"],"kind":"event","category":["process"],"dataset":"application","action":"handle_packet","reason":"SSH shell handling error","outcome":"failure"}},"error":{{"message":"{e}"')
		finally:
			channel.close()

	# Stops the SSH server.
	def stop(self):
		logger.info(f'"type":["end"],"kind":"event","category":["process"],"dataset":"application","action":"stop","reason":"SSH server emulator is stopping","outcome":"success"')
		self.running = False
		if self.server_socket:
			self.server_socket.close()  # Interrupt the blocking accept() call
			self.server_socket = None
		if self.transport:
			self.transport.close()
			self.transport = None
		if self.thread:
			self.thread.join()  # Wait for the server thread to finish
			self.thread = None

		logger.info(f'"type":["end"],"kind":"event","category":["process"],"dataset":"application","action":"stop","reason":"SSH server emulator has stopped","outcome":"success"')

	# Generates a self-signed certificate and private key if they do not already exist.
	def get_ssh_key(self):
		key_path = "./emulators/ssh_key"

		if not os.path.exists(key_path):
			logger.info(f'"type":["info","creation"],"kind":"event","category":["configuration"],"dataset":"application","action":"get_ssh_key","reason":"Generating new SSH RSA key {key_path}","outcome":"success"')
			# Generate a new RSA key
			key = RSAKey.generate(2048)
			key.write_private_key_file(key_path)
		else:
			# Read the existing key from the file
			logger.debug(f'"type":["info","creation"],"kind":"event","category":["configuration"],"dataset":"application","action":"get_ssh_key","reason":"RSA key {key_path} already exists","outcome":"success"')
			key = RSAKey(filename=key_path)
		
		return key
