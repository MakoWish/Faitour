import asyncio
import utils.config
from utils.logger import logger
from pysnmp.entity import engine, config
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.entity.rfc3413 import cmdrsp
from pysnmp.entity.rfc3413.context import SnmpContext


class SNMPServer:
	def __init__(self):
		self.running = False
		self.community = utils.config.get_service_by_name("snmp")["community"]
		self.host_ip = utils.config.get_value("network.adapter.ip")
		self.host_port = utils.config.get_service_by_name("snmp")["port"]
		self.snmp_engine = engine.SnmpEngine()
		self.snmp_context = None  # Will hold the SnmpContext instance
		self.loop = asyncio.get_event_loop()

	# Configure SNMP server with a community string and transport.
	def configure(self):
		try:
			logger.info(f'"type":["info"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"configure","reason":"SNMP server emulator is starting on {self.host_ip}:{self.host_port}","outcome":"unknown"}},"server":{{"ip":"{self.host_ip}","port":{self.host_port}')

			# Add SNMPv2c community to the engine
			config.addV1System(self.snmp_engine, 'my-area', self.community)

			# Allow access for this community
			config.addVacmUser(
				self.snmp_engine,
				2,  # SNMPv2c
				'my-area',
				'noAuthNoPriv',
				(1, 3, 6, 1, 2, 1),  # Allow access to MIB-2 (OID: .1.3.6.1.2.1)
				(1, 3, 6, 1, 2, 1)   # Allow writing to MIB-2 (if needed)
			)

			# Set up the UDP transport (bind to IP and port)
			transport = udp.UdpTransport().openServerMode((self.host_ip, self.host_port))
			config.addTransport(self.snmp_engine, udp.domainName, transport)

			# Initialize SnmpContext
			self.snmp_context = SnmpContext(self.snmp_engine)

			# Register command responder applications with the context
			cmdrsp.GetCommandResponder(self.snmp_engine, self.snmp_context)
			cmdrsp.SetCommandResponder(self.snmp_engine, self.snmp_context)
			cmdrsp.NextCommandResponder(self.snmp_engine, self.snmp_context)
			cmdrsp.BulkCommandResponder(self.snmp_engine, self.snmp_context)

			logger.info(f'"type":["start"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"configure","reason":"SNMP server emulator has started on {self.host_ip}:{self.host_port}","outcome":"success"}},"server":{{"ip":"{self.host_ip}","port":{self.host_port}')

		except Exception as e:
			logger.error(f'"type":["end"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"configure","reason":"Error configuring SNMP server","outcome":"failure"}},"error":{{"message":"{e}"')
			raise
		
	# Start the SNMP server and handle requests asynchronously.
	def start(self):
		try:
			self.running = True
			dispatcher = self.snmp_engine.transportDispatcher

			if dispatcher is None:
				logger.error(f'"type":["error"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"configure","reason":"Transport dispatcher not initialized","outcome":"failure"}},"error":{{"message":"Transport dispatcher not initialized"')

			# Job Started signals that dispatcher will process requests
			dispatcher.jobStarted(1)
			dispatcher.runDispatcher()
		except Exception as e:
			logger.error(f'"type":["error"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"start","reason":"SNMP server emulator error","outcome":"failure"}},"error":{{"message":"{e}"')
	
	# Stop the SNMP server gracefully.
	def stop(self):
		try:
			logger.info(f'"type":["end"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"stop","reason":"SNMP server emulator is stopping","outcome":"success"')
			self.running = False
			dispatcher = self.snmp_engine.transportDispatcher

			if dispatcher:
				dispatcher.closeDispatcher()
				logger.info(f'"type":["end"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"stop","reason":"SNMP server emulator has stopped","outcome":"success"')
		except Exception as e:
			logger.error(f'"type":["error"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"stop","reason":"SNMP server emulator failed to stop","outcome":"failure"}},"error":{{"message":"{e}"')
