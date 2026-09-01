import shlex
from pathlib import Path


class VirtualShell:
	"""A small, non-executing shell backed by a confined directory tree."""

	def __init__(self, root_dir, start_dir="home/admin"):
		self.root = Path(root_dir).resolve()
		self.root.mkdir(parents=True, exist_ok=True)
		self.cwd = self._resolve(start_dir)
		self.cwd.mkdir(parents=True, exist_ok=True)

	def _resolve(self, path):
		candidate = Path(path)
		if candidate.is_absolute():
			candidate = self.root / str(candidate).lstrip("/")
		else:
			candidate = self.cwd / candidate if hasattr(self, "cwd") else self.root / candidate
		resolved = candidate.resolve()
		try:
			resolved.relative_to(self.root)
		except ValueError as exc:
			raise PermissionError("Access denied") from exc
		return resolved

	def run(self, command):
		try:
			args = shlex.split(command)
		except ValueError as exc:
			return f"shell: {exc}"
		if not args:
			return ""

		name = args[0]
		try:
			if name == "pwd":
				relative = self.cwd.relative_to(self.root)
				return "/" + (str(relative) if str(relative) != "." else "")
			if name == "cd":
				target = self._resolve(args[1] if len(args) > 1 else "/home/admin")
				if not target.is_dir():
					return f"cd: {args[-1]}: No such directory"
				self.cwd = target
				return ""
			if name in {"ls", "dir"}:
				target = self._resolve(args[1] if len(args) > 1 else ".")
				return "\n".join(sorted(item.name for item in target.iterdir()))
			if name in {"cat", "type"}:
				if len(args) != 2:
					return f"Usage: {name} FILE"
				return self._resolve(args[1]).read_text(errors="replace")
			if name == "whoami":
				return "admin"
			if name == "uname":
				return "Linux localhost 5.15.0 x86_64 GNU/Linux"
			if name == "echo":
				return " ".join(args[1:])
			if name == "help":
				return "Available commands: cat, cd, dir, echo, help, ls, pwd, type, uname, whoami"
		except (OSError, PermissionError) as exc:
			return f"{name}: {exc}"

		return f"{name}: command not found"
