import time
import secrets
import socket
from utils.ntfy import get_peer_socket
from structs import SocketAddress
from enums import NATType
import logging

PEER_ADDRESS_FETCH_INTERVAL = 5
MAX_PEER_ADDRESS_RESOLUTIONS = float("inf")
MAX_PUNCH_ATTEMPTS = float("inf")
PUNCH_INTERVAL = 10
PEER_RECV_TIMEOUT = 0.5

PREFIX_PING = "PING"
PREFIX_PONG = "PONG"
PREFIX_ACK = "ACK"

log = logging.getLogger("p2p")


def punch_udp_hole(
    sock: socket.socket,
    peer_addr: SocketAddress,
    peer_topic: str,
    peer_username: str,
    own_username: str,
) -> bool:
    ping_id = secrets.token_hex(12)
    deadline = time.monotonic() + MAX_PUNCH_ATTEMPTS * PUNCH_INTERVAL
    next_ping = 0.0

    while time.monotonic() < deadline:
        now = time.monotonic()

        if now >= next_ping:
            while True:
                try:
                    peer_addr, peer_nat = get_peer_socket(peer_topic, peer_username)
                    log.info("Fetched new peer address.")
                    break
                except Exception as e:
                    log.exception(e)
                    continue

            if peer_nat == NATType.SYMMETRIC:
                log.info("Peer's NAT is syemmetric, punch may not be possible")

            sock.connect((peer_addr.ip, peer_addr.port))
            sock.send(f"{PREFIX_PING}:{ping_id}".encode("utf-8"))
            log.info(f"Sent ping-{ping_id} to peer.")
            next_ping = now + PUNCH_INTERVAL

        try:
            message = sock.recv(2048)
        except socket.timeout:
            continue

        payload = message.decode("utf-8", errors="replace")
        if payload.startswith(PREFIX_PING):
            peer_ping_id = payload.split(":", 1)[1]
            if peer_username < own_username:
                ping_id = peer_ping_id

            sock.send(f"{PREFIX_PONG}:{ping_id}".encode("utf-8"))
            log.info("Recived ping, sent pong.")

        elif payload.startswith(PREFIX_PONG):
            log.info("Recived pong.")
            pong_id = payload.split(":", 1)[1]
            if pong_id != ping_id:
                log.info("Pong does not match the ping id.")
                continue

            sock.send(f"{PREFIX_ACK}:{pong_id}".encode("utf-8"))
            log.info("Sent ACK.")
            return True

        elif payload.startswith(PREFIX_ACK):
            log.info("Recived ACK.")
            ack_id = payload.split(":", 1)[1]
            if ack_id == ping_id:
                return True
            else:
                log.info("ACK id does not match ping id.")

    return False
