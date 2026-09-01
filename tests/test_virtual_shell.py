import tempfile
import unittest
from pathlib import Path

from utils.virtual_shell import VirtualShell


class VirtualShellTests(unittest.TestCase):
	def setUp(self):
		self.temp_dir = tempfile.TemporaryDirectory()
		root = Path(self.temp_dir.name)
		(root / "home/admin").mkdir(parents=True)
		(root / "home/admin/note.txt").write_text("decoy data")
		self.shell = VirtualShell(root)

	def tearDown(self):
		self.temp_dir.cleanup()

	def test_supported_commands_use_virtual_filesystem(self):
		self.assertEqual(self.shell.run("pwd"), "/home/admin")
		self.assertEqual(self.shell.run("cat note.txt"), "decoy data")
		self.assertEqual(self.shell.run("echo hello world"), "hello world")

	def test_commands_are_not_executed_by_host_shell(self):
		self.assertEqual(self.shell.run("id"), "id: command not found")
		self.assertEqual(self.shell.run("echo safe; touch escaped"), "safe; touch escaped")
		self.assertFalse((Path(self.temp_dir.name) / "home/admin/escaped").exists())

	def test_path_traversal_is_rejected(self):
		self.assertIn("Access denied", self.shell.run("cat ../../../../etc/passwd"))


if __name__ == "__main__":
	unittest.main()
