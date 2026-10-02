import json
from dataclasses import dataclass, field


@dataclass
class Command:
    type: str
    params: dict = field(default_factory=dict)


@dataclass
class Response:
    status: str
    data: dict | None = None
    message: str | None = None

    def to_json(self) -> str:
        d = {"status": self.status}
        if self.data is not None:
            d["data"] = self.data
        if self.message is not None:
            d["message"] = self.message
        return json.dumps(d)


def parse_command(line: str) -> Command:
    obj = json.loads(line)
    return Command(type=obj["type"], params=obj.get("params", {}))


def ok(data: dict | None = None) -> Response:
    return Response(status="ok", data=data)


def error(message: str) -> Response:
    return Response(status="error", message=message)


def progress(data: dict) -> Response:
    return Response(status="progress", data=data)
