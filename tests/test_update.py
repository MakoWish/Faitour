import tempfile
import unittest
from pathlib import Path
from zipfile import ZipFile

try:
	from update import validate_archive_members, version_key
except ModuleNotFoundError:
	validate_archive_members = version_key = None


@unittest.skipIf(version_key is None, "runtime updater dependencies are not installed")
class UpdateTests(unittest.TestCase):
	def test_versions_are_compared_numerically(self):
		self.assertGreater(version_key("2.10.0"), version_key("2.9.0"))

	def test_archive_traversal_is_rejected(self):
		with tempfile.TemporaryDirectory() as directory:
			archive = Path(directory) / "bad.zip"
			with ZipFile(archive, "w") as output:
				output.writestr("../escaped", "bad")
			with ZipFile(archive) as source:
				with self.assertRaises(ValueError):
					validate_archive_members(source, Path(directory) / "destination")


if __name__ == "__main__":
	unittest.main()
