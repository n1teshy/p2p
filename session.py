from __future__ import annotations

import logging
import random
import socket
import time
from dataclasses import dataclass
from typing import Optional
from enum import Enum
import secrets

from ntfy import ntfy_get_latest_peer, ntfy_publish
from stun import discover_public_endpoint, NATType

log = logging.getLogger("p2p")

PEER_ADDRESS_FETCH_INTERVAL = 5
MAX_PEER_ADDRESS_RESOLUTIONS = float("inf")
MAX_PUNCH_ATTEMPTS = float("inf")
PUNCH_INTERVAL = 10
PEER_RECV_TIMEOUT = 0.5

PREFIX_PING = "PING"
PREFIX_PONG = "PONG"
PREFIX_ACK = "ACK"


class SessionState(int, Enum):
    SELF_DISCOVERY = 0
    PEER_DISCOVERY = 1
    UDP_PUNCH = 2
    CONNECTED = 3


@dataclass
class Session:
    sock: socket.socket

    my_username: str
    my_topic: str
    peer_username: str
    peer_topic: str

    my_ip: str | None = None
    my_port: int | None = None
    my_nat_type: NATType | None = None
    peer_ip: str | None = None
    peer_port: int | None = None

    ping_id: str | None = None

    state: SessionState = SessionState.SELF_DISCOVERY


def discover_self(session: Session) -> Session:
    log.info(f"Getting own public address...")
    stun, nat_type = discover_public_endpoint(session.sock, True)
    session.my_nat_type = nat_type
    session.my_ip, session.my_port = stun.ip, stun.port
    return session


def discover_peer(session: Session) -> Session:
    log.info(f"Getting {session.peer_username}'s address...")
    no_attempts = 0
    peer_address = None
    while peer_address is None and no_attempts < MAX_PEER_ADDRESS_RESOLUTIONS:
        peer_address = ntfy_get_latest_peer(session.peer_topic, session.peer_username)
        no_attempts += 1
        if peer_address is None:
            log.info(f"Attempt:{no_attempts} Could not get peer's address.")
            time.sleep(PEER_ADDRESS_FETCH_INTERVAL)
            continue

    if peer_address is None:
        return session

    session.peer_ip = peer_address[0]
    session.peer_port = peer_address[1]
    return session


def punch_udp_hole(session: Session) -> Session:
    log.info("Punching...")
    session.sock.connect((session.peer_ip, session.peer_port))
    session.sock.settimeout(PEER_RECV_TIMEOUT)

    if session.ping_id is None:
        session.ping_id = secrets.token_hex(12)

    deadline = time.monotonic() + MAX_PUNCH_ATTEMPTS * PUNCH_INTERVAL
    next_ping = 0.0

    while time.monotonic() < deadline:
        now = time.monotonic()

        if now >= next_ping:
            discover_peer(session)
            session.sock.connect((session.peer_ip, session.peer_port))
            log.info("Re-published own address.")

            session.sock.send(f"{PREFIX_PING}:{session.ping_id}".encode("utf-8"))
            log.info("Sent new ping.")
            next_ping = now + PUNCH_INTERVAL

        try:
            message = session.sock.recv(2048)
        except socket.timeout:
            continue

        payload = message.decode("utf-8", errors="replace")
        if payload.startswith(PREFIX_PING):
            peer_ping_id = payload.split(":", 1)[1]
            if session.peer_username < session.my_username:
                session.ping_id = peer_ping_id

            session.sock.send(f"{PREFIX_PONG}:{session.ping_id}".encode("utf-8"))
            log.info("Recived ping, sent pong.")

        elif payload.startswith(PREFIX_PONG):
            log.info("Recived pong.")
            pong_id = payload.split(":", 1)[1]
            if pong_id != session.ping_id:
                log.info("Pong does not match the ping id.")
                continue

            session.sock.send(f"{PREFIX_ACK}:{pong_id}".encode("utf-8"))
            log.info("Sent ACK.")
            session.state = SessionState.CONNECTED
            return session

        elif payload.startswith(PREFIX_ACK):
            log.info("Recived ACK.")
            ack_id = payload.split(":", 1)[1]
            if ack_id == session.ping_id:
                session.state = SessionState.CONNECTED
                return session
            else:
                log.info("ACK id does not match ping id.")

    return session


def run_session(session: Session) -> Session:
    session = discover_self(session)
    if session.my_nat_type == NATType.SYMMETRIC:
        log.error("Symmetric NAT detected, punching is not possible.")
        return False

    session.state = SessionState.PEER_DISCOVERY
    session = discover_peer(session)

    session.state = SessionState.UDP_PUNCH
    session = punch_udp_hole(session)
    return session
