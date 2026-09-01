import unittest
from unittest.mock import patch

try:
	from utils import config
except ModuleNotFoundError:
	config = None


@unittest.skipIf(config is None, "runtime configuration dependencies are not installed")
class ConfigValidationTests(unittest.TestCase):
	def test_repository_defaults_are_invalid(self):
		errors = config.validation_errors(check_interface=False)
		self.assertIn("network.adapter.name must be configured", errors)

	def test_duplicate_enabled_ports_are_invalid(self):
		custom = {
			"network": {"adapter": {"name": "eth0", "ip": "192.0.2.1", "mac": "02:00:00:00:00:01"}},
			"logging": {"level": "INFO"},
			"services": [
				{"name": "one", "enabled": True, "port": 80},
				{"name": "two", "enabled": True, "port": 80},
			],
		}
		with patch.object(config, "config", custom):
			self.assertIn("enabled services must use unique ports", config.validation_errors(check_interface=False))


if __name__ == "__main__":
	unittest.main()
