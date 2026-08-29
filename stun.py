from __future__ import annotations

import logging
import random
import socket
import struct
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger("p2p")

STUN_SERVERS = [
    ("stun.l.google.com", 19302),
    ("stun.cloudflare.com", 3478),
]

STUN_MAGIC_COOKIE = 0x2112A442
STUN_BINDING_REQUEST = 0x0001
STUN_BINDING_SUCCESS = 0x0101

ATTR_MAPPED_ADDRESS = 0x0001
ATTR_XOR_MAPPED_ADDRESS = 0x0020

STUN_FAMILY_IPV4 = 0x01


@dataclass
class StunResult:
    ip: str
    port: int


def build_stun_binding_request(transaction_id: bytes) -> bytes:
    return struct.pack("!HHI12s", STUN_BINDING_REQUEST, 0, STUN_MAGIC_COOKIE, transaction_id)


def extract_mapped_address_from_stun_response(data: bytes, transaction_id: bytes) -> Optional[StunResult]:
    if len(data) < 20:
        return None

    message_type, attributes_length, magic_cookie, response_transaction_id = struct.unpack("!HHI12s", data[:20])

    if (
        message_type != STUN_BINDING_SUCCESS
        or magic_cookie != STUN_MAGIC_COOKIE
        or response_transaction_id != transaction_id
    ):
        return None

    attributes = data[20:20 + attributes_length]
    mapped_address = None
    offset = 0

    while offset + 4 <= len(attributes):
        attr_type, attr_length = struct.unpack("!HH", attributes[offset:offset + 4])
        start, end = offset + 4, offset + 4 + attr_length

        if end > len(attributes):
            break

        value = attributes[start:end]

        if attr_type == ATTR_XOR_MAPPED_ADDRESS and len(value) >= 8 and value[1] == STUN_FAMILY_IPV4:
            xor_port = struct.unpack("!H", value[2:4])[0]
            port = xor_port ^ (STUN_MAGIC_COOKIE >> 16)

            xor_address = struct.unpack("!I", value[4:8])[0]
            address = xor_address ^ STUN_MAGIC_COOKIE
            ip = socket.inet_ntoa(struct.pack("!I", address))

            return StunResult(ip, port)

        elif attr_type == ATTR_MAPPED_ADDRESS and len(value) >= 8 and value[1] == STUN_FAMILY_IPV4:
            port = struct.unpack("!H", value[2:4])[0]
            ip = socket.inet_ntoa(value[4:8])
            mapped_address = StunResult(ip, port)

        offset += 4 + attr_length
        offset += (4 - attr_length % 4) % 4

    return mapped_address


def stun_query(sock: socket.socket, host: str, port: int, timeout: float = 3.0) -> StunResult:
    transaction_id = bytes(random.getrandbits(8) for _ in range(12))
    request = build_stun_binding_request(transaction_id)
    server_ip = socket.gethostbyname(host)

    sock.settimeout(timeout)
    sock.sendto(request, (server_ip, port))
    data, _ = sock.recvfrom(2048)

    result = extract_mapped_address_from_stun_response(data, transaction_id)

    if result is None:
        raise RuntimeError(f"STUN server {host}:{port} returned invalid response")

    return result


def discover_public_endpoint(sock: socket.socket, quiet: bool = False) -> tuple[StunResult, str]:
    results = []

    for host, port in STUN_SERVERS:
        try:
            result = stun_query(sock, host, port)
            if not quiet:
                log.info("STUN %s:%d -> %s:%d", host, port, result.ip, result.port)
            results.append(result)
        except (socket.timeout, OSError, RuntimeError) as exc:
            log.warning("STUN %s:%d failed: %s", host, port, exc)

    if not results:
        raise RuntimeError("all STUN servers failed")

    nat_type = "symmetric" if len(results) >= 2 and results[0].port != results[1].port else "cone-type"

    return results[0], nat_type
