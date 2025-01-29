import threading
import utils.config as config
from emulators.ftp import FTPServerEmulator
from emulators.http import WebServer
from emulators.mssql import MSSQLEmulator
from emulators.mysql import MySQLEmulator
from emulators.postgresql import PostgreSQLServer
from emulators.rdp import RDServer
from emulators.smbv2 import SMBv2Server
from emulators.snmp import SNMPServer
from emulators.ssh import SSHServer
from emulators.telnet import TelnetServer


#===============================================================================
# Class for starting and stopping any enabled emulators
#===============================================================================
class ServiceEmulators:
	def __init__(self):
		self.ftp_server = FTPServerEmulator()
		self.http_server = WebServer(http_enabled=False, https_enabled=False)
		self.mssql_server = MSSQLEmulator()
		self.mysql_server = MySQLEmulator()
		self.postgresql_server = PostgreSQLServer()
		self.rdp_server = RDServer()
		self.smb_server = SMBv2Server()
		self.snmp_server = SNMPServer()
		self.ssh_server = SSHServer()
		self.telnet_server = TelnetServer()

	# Check for and start emulators that are enabled
	def start(self):
		# FTP
		if config.get_service_by_name("ftp")["enabled"]:
			ftp_thread = threading.Thread(target=self.start_ftp_server)
			ftp_thread.daemon = True
			ftp_thread.start()

		# HTTP(S)
		http_enabled = config.get_service_by_name("http")["enabled"]
		https_enabled = config.get_service_by_name("https")["enabled"]
		if http_enabled or https_enabled:
			self.http_server = WebServer(http_enabled=http_enabled, https_enabled=https_enabled)
			http_thread = threading.Thread(target=self.start_web_servers)
			http_thread.daemon = True
			http_thread.start()

		# PostgreSQL
		if config.get_service_by_name("postgresql")["enabled"]:
			postgresql_thread = threading.Thread(target=self.start_postgresql_server)
			postgresql_thread.daemon = True
			postgresql_thread.start()

		# MSSQL
		if config.get_service_by_name("mssql")["enabled"]:
			mssql_thread = threading.Thread(target=self.start_mssql_server)
			mssql_thread.daemon = True
			mssql_thread.start()

		# MySQL
		if config.get_service_by_name("mysql")["enabled"]:
			mysql_thread = threading.Thread(target=self.start_mysql_server)
			mysql_thread.daemon = True
			mysql_thread.start()

		# RDP
		if config.get_service_by_name("rdp")["enabled"]:
			rdp_thread = threading.Thread(target=self.start_rdp_server)
			rdp_thread.daemon = True
			rdp_thread.start()

		# SMBv2
		if config.get_service_by_name("smb")["enabled"]:
			smb_thread = threading.Thread(target=self.start_smb_server)
			smb_thread.daemon = True
			smb_thread.start()

		# SNMP
		if config.get_service_by_name("snmp")["enabled"]:
			self.snmp_server.configure()
			snmp_thread = threading.Thread(target=self.start_snmp_agent)
			snmp_thread.daemon = True
			snmp_thread.start()

		# SSH
		if config.get_service_by_name("ssh")["enabled"]:
			ssh_thread = threading.Thread(target=self.start_ssh_server)
			ssh_thread.daemon = True
			ssh_thread.start()

		# Telnet
		if config.get_service_by_name("telnet")["enabled"]:
			telnet_thread = threading.Thread(target=self.start_telnet_server)
			telnet_thread.daemon = True
			telnet_thread.start()

	# Check for and start emulators that are enabled
	def stop(self):
		if self.ftp_server.running:
			self.ftp_server.stop()
		if self.http_server.running:
			self.http_server.stop_servers()
		if self.mssql_server.running:
			self.mssql_server.stop()
		if self.mysql_server.running:
			self.mysql_server.stop()
		if self.postgresql_server.running:
			self.postgresql_server.stop()
		if self.rdp_server.running:
			self.rdp_server.stop()
		if self.smb_server.running:
			self.smb_server.stop()
		if self.snmp_server.running:
			self.snmp_server.stop()
		if self.ssh_server.running:
			self.ssh_server.stop()
		if self.telnet_server.running:
			self.telnet_server.stop()

	# Start FTP server
	def start_ftp_server(self):
		self.ftp_server.start()

	# Start HTTP server
	def start_web_servers(self):
		self.http_server.start_servers()

	# Start MSSQL server
	def start_mssql_server(self):
		self.mssql_server.start()

	# Start MySQL server
	def start_mysql_server(self):
		self.mysql_server.start()

	# Start PostgreSQL server
	def start_postgresql_server(self):
		self.postgresql_server.start()

	# Start RDP server
	def start_rdp_server(self):
		self.rdp_server.start()

	# Start SMB server
	def start_smb_server(self):
		self.smb_server.start()

	# Start SNMP server
	def start_snmp_agent(self):
		self.snmp_server.start()

	# Start SSH server
	def start_ssh_server(self):
		self.ssh_server.start()

	# Start telnet server
	def start_telnet_server(self):
		self.telnet_server.start()
