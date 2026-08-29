from __future__ import annotations

import logging
import random
import socket
import time
from dataclasses import dataclass
from typing import Optional

from ntfy import ntfy_get_latest_peer, ntfy_publish
from stun import discover_public_endpoint

log = logging.getLogger("p2p")

POLL_INTERVAL = 10.0
ANNOUNCE_INTERVAL = 10.0

PUNCH_RETRY_INTERVAL = 0.5
PUNCH_ATTEMPT_TIMEOUT = 5.0

# Heartbeat keeps the "connected" phase honest so we can detect a dead link
# without ever going back to bursty punching while things are still working.
HEARTBEAT_INTERVAL = 5.0
HEARTBEAT_TIMEOUT = 20.0

# How often to send an application-level message once connected. Runs
# indefinitely until the connection drops or the process is interrupted.
MESSAGE_INTERVAL = 1.0

RECV_TICK = 0.5  # how long each loop iteration blocks waiting for a packet


# ----------------------------------------------------------------------
# WIRE PROTOCOL
# ----------------------------------------------------------------------
# PING:<user>:<nonce>   - punch/heartbeat probe, always answered with PONG
# PONG:<nonce>          - reply to a PING, matched against a pending nonce
# MSG:<user>:<text>     - application message, always answered with ACK
# ACK:<text>            - acknowledgement of a MSG

def send_ping(sock: socket.socket, addr: tuple[str, int], username: str, nonce: str) -> None:
    try:
        sock.sendto(f"PING:{username}:{nonce}".encode(), addr)
    except OSError:
        pass


def send_pong(sock: socket.socket, addr: tuple[str, int], nonce: str) -> None:
    try:
        sock.sendto(f"PONG:{nonce}".encode(), addr)
    except OSError:
        pass


def send_message(sock: socket.socket, addr: tuple[str, int], username: str, message: str) -> None:
    try:
        sock.sendto(f"MSG:{username}:{message}".encode(), addr)
        log.info("SENT -> %s:%d: %s", *addr, message)
    except OSError:
        pass


def send_ack(sock: socket.socket, addr: tuple[str, int], message: str) -> None:
    try:
        sock.sendto(f"ACK:{message}".encode(), addr)
    except OSError:
        pass


# ----------------------------------------------------------------------
# SESSION STATE MACHINE
#
#   seeking   -> waiting on ntfy for the peer's current endpoint
#   punching  -> bursting PINGs at a known endpoint, trying to open the NAT
#   connected -> link is up; no punching, just a slow heartbeat for liveness
#
# Punching only ever happens on entry to "seeking" finding a peer, or when
# the heartbeat in "connected" times out and we fall back to "seeking".
# Incoming PINGs are answered unconditionally in every phase.
# ----------------------------------------------------------------------

@dataclass
class Session:
    username: str
    my_topic: str
    peer_username: str
    peer_topic: str

    phase: str = "seeking"
    peer_addr: Optional[tuple[str, int]] = None
    last_polled_peer: Optional[tuple[str, int]] = None

    pending_nonce: Optional[str] = None
    punch_deadline: float = 0.0
    next_punch_send: float = 0.0

    last_rx: float = 0.0
    next_heartbeat: float = 0.0
    next_message: float = 0.0
    message_counter: int = 0

    next_announce: float = 0.0
    next_poll: float = 0.0


def handle_packet(sock: socket.socket, session: Session, data: bytes, addr: tuple[str, int]) -> None:
    text = data.decode(errors="ignore")

    if text.startswith("PING:"):
        parts = text.split(":", 2)
        if len(parts) == 3:
            _, their_user, their_nonce = parts
            log.info("Received PING from %s (%s:%d)", their_user, *addr)
            send_pong(sock, addr, their_nonce)  # always answer, regardless of phase
            if session.phase == "connected" and addr == session.peer_addr:
                session.last_rx = time.time()
        return

    if text.startswith("PONG:"):
        nonce = text.split(":", 1)[1]
        if session.phase == "punching" and nonce == session.pending_nonce:
            log.info("Received PONG from %s:%d", *addr)
            session.phase = "connected"
            session.peer_addr = addr
            session.pending_nonce = None
            session.last_rx = time.time()
            session.next_heartbeat = time.time() + HEARTBEAT_INTERVAL
            session.next_message = time.time() + MESSAGE_INTERVAL
            log.info("Direct P2P connection established with %s", session.peer_username)
        return

    if text.startswith("MSG:"):
        parts = text.split(":", 2)
        if len(parts) == 3:
            _, their_user, message = parts
            log.info("RECEIVED <- %s:%d [%s]: %s", *addr, their_user, message)
            send_ack(sock, addr, message)
            if session.phase == "connected" and addr == session.peer_addr:
                session.last_rx = time.time()
        return

    if text.startswith("ACK:"):
        if session.phase == "connected" and addr == session.peer_addr:
            session.last_rx = time.time()
        return


def start_punch(session: Session, peer_addr: tuple[str, int]) -> None:
    now = time.time()
    session.phase = "punching"
    session.peer_addr = peer_addr
    session.pending_nonce = str(random.randint(0, 1_000_000))
    session.punch_deadline = now + PUNCH_ATTEMPT_TIMEOUT
    session.next_punch_send = 0.0
    log.info("Punching %s:%d", *peer_addr)


def drop_connection(session: Session, reason: str) -> None:
    log.warning("Connection to %s lost (%s)", session.peer_username, reason)
    session.phase = "seeking"
    session.peer_addr = None
    session.pending_nonce = None
    # Forget the last address we punched so a fresh ntfy poll re-triggers a
    # punch attempt even if the peer's endpoint hasn't actually changed.
    session.last_polled_peer = None


def tick(sock: socket.socket, session: Session) -> None:
    now = time.time()

    # Keep our own published endpoint fresh regardless of phase (cheap, quiet).
    if now >= session.next_announce:
        try:
            endpoint, nat_type = discover_public_endpoint(sock, quiet=True)
            ntfy_publish(
                session.my_topic,
                {"user": session.username, "ip": endpoint.ip, "port": endpoint.port, "nat_type": nat_type},
                quiet=True,
            )
        except RuntimeError as exc:
            log.warning("Endpoint refresh failed: %s", exc)
        session.next_announce = now + ANNOUNCE_INTERVAL

    # Poll the peer's published endpoint unconditionally, in every phase -
    # not just while "seeking". Any time the address on ntfy differs from
    # whatever we last acted on, treat it as authoritative and re-punch
    # immediately, even if we're already mid-punch or fully connected. This
    # covers a peer picking up a stale/incorrect endpoint from an earlier
    # publish, or the local NAT remapping the external port mid-session.
    if now >= session.next_poll:
        peer = ntfy_get_latest_peer(session.peer_topic, session.peer_username)
        session.next_poll = time.time() + POLL_INTERVAL

        if peer is not None and peer != session.last_polled_peer:
            session.last_polled_peer = peer
            log.info("Peer endpoint changed -> %s:%d (phase was %s)", peer[0], peer[1], session.phase)
            start_punch(session, peer)
            return  # phase just changed to "punching"; nothing else to do this tick

    if session.phase == "punching":
        if now >= session.punch_deadline:
            log.warning("Could not establish P2P connection to %s:%d", *session.peer_addr)
            session.phase = "seeking"
            session.peer_addr = None
            session.pending_nonce = None
        elif now >= session.next_punch_send:
            send_ping(sock, session.peer_addr, session.username, session.pending_nonce)
            session.next_punch_send = now + PUNCH_RETRY_INTERVAL

    elif session.phase == "connected":
        if now - session.last_rx > HEARTBEAT_TIMEOUT:
            drop_connection(session, "heartbeat timeout")
            return

        if now >= session.next_message:
            session.message_counter += 1
            send_message(sock, session.peer_addr, session.username, f"hello-{session.message_counter}")
            session.next_message = now + MESSAGE_INTERVAL

        if now >= session.next_heartbeat:
            # Liveness probe only - not a punch burst. Peer answers it via the
            # unconditional PING handler above.
            send_ping(sock, session.peer_addr, session.username, "heartbeat")
            session.next_heartbeat = now + HEARTBEAT_INTERVAL


def run_session(
    sock: socket.socket,
    username: str,
    my_topic: str,
    peer_username: str,
    peer_topic: str,
    initial_connect_timeout: float,
) -> bool:
    session = Session(username=username, my_topic=my_topic, peer_username=peer_username, peer_topic=peer_topic)

    connect_deadline = time.time() + initial_connect_timeout
    ever_connected = False

    sock.settimeout(RECV_TICK)

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            handle_packet(sock, session, data, addr)
        except socket.timeout:
            pass

        tick(sock, session)

        if session.phase == "connected":
            ever_connected = True
        elif not ever_connected and time.time() >= connect_deadline:
            log.warning("Timed out waiting for initial connection to %s", peer_username)
            return False
        # Once connected, the session runs indefinitely (reconnecting on
        # failure via "seeking" -> "punching") until interrupted.
