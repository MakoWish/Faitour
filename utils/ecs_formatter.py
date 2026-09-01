import json
import logging


class ECSFormatter(logging.Formatter):
	def format(self, record):
		timestamp = self.formatTime(record, "%Y-%m-%dT%H:%M:%S") + f".{int(record.msecs):03d}"
		base = {
			"timestamp": timestamp,
			"log": {"level": record.levelname, "logger": record.name,
				"origin": {"file": {"line": record.lineno, "name": record.pathname}}},
			"event": {"provider": record.module},
		}
		message = record.getMessage()
		try:
			fields = json.loads('{"event":{' + message + '}}')
			base["event"].update(fields.pop("event", {}))
			base.update(fields)
		except (json.JSONDecodeError, TypeError, ValueError):
			base["event"].update({"kind": "event", "category": ["process"], "outcome": "unknown"})
			base["message"] = message
		if record.exc_info:
			base.setdefault("error", {})["stack_trace"] = self.formatException(record.exc_info)
		return json.dumps(base, ensure_ascii=False, separators=(",", ":"))
