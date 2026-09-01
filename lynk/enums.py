from enum import Enum


class NATType(int, Enum):
    SYMMETRIC = 0
    CONE = 1


class SessionState(int, Enum):
    SELF_DISCOVERY = 0
    PEER_DISCOVERY = 1
    UDP_PUNCH = 2
    CONNECTED = 3
