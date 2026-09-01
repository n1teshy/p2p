from dataclasses import dataclass


@dataclass
class SocketAddress:
    ip: str
    port: int
