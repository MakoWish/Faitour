import json
import logging
import unittest

from utils.ecs_formatter import ECSFormatter


class ECSFormatterTests(unittest.TestCase):
	def test_valid_event_fragment_is_structured_json(self):
		record = logging.LogRecord("test", logging.INFO, __file__, 10,
			'"kind":"alert","reason":"captured"},"user":{"password":"plain-text"', (), None)
		payload = json.loads(ECSFormatter().format(record))
		self.assertEqual(payload["event"]["kind"], "alert")
		self.assertEqual(payload["user"]["password"], "plain-text")

	def test_attacker_controlled_invalid_fragment_still_emits_json(self):
		record = logging.LogRecord("test", logging.INFO, __file__, 10,
			'"reason":"bad\n\"value"', (), None)
		payload = json.loads(ECSFormatter().format(record))
		self.assertIn("message", payload)


if __name__ == "__main__":
	unittest.main()
