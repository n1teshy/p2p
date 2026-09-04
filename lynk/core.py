import socket
import typing as t
from lynk.enums import NATType
from dataclasses import dataclass
from lynk.utils.stun import discover_public_socket
import logging
from lynk.utils.ntfy import channel_for
from lynk.utils.ntfy import get_peer_socket, publish
from lynk.utils.net import punch_udp_hole, PEER_RECV_TIMEOUT
from lynk.structs import SocketAddress

log = logging.getLogger("p2p")


@dataclass
class PeerInfo:
    username: str
    address: SocketAddress
    nat: NATType


@dataclass
class NTFYPeerInfo(PeerInfo):
    topic: str


class Lynk:
    @staticmethod
    def from_usernames(own_username: str, peer_username: str):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("0.0.0.0", 0))
        sock.settimeout(PEER_RECV_TIMEOUT)

        own_ntfy_topic = channel_for(own_username)
        peer_ntfy_topic = channel_for(peer_username)
        own_addr, own_nat = discover_public_socket(sock)
        log.info(f"Own address is {own_addr.ip}:{own_addr.port}")

        if own_nat == NATType.SYMMETRIC:
            log.warning("Own NAT type is symmetric, punching may not be possible.")

        publish(
            own_ntfy_topic,
            {
                "username": own_username,
                "ip": own_addr.ip,
                "port": own_addr.port,
                "nat": own_nat.value,
            },
        )
        log.info("Published own address")

        while True:
            try:
                peer_info = get_peer_socket(peer_ntfy_topic, peer_username)
                if peer_info is None:
                    continue

                peer_addr, peer_nat = peer_info
                log.info(f"Peer address is {own_addr.ip}:{own_addr.port}")
                break
            except Exception as e:
                log.exception(e)
                continue

        if peer_nat == NATType.SYMMETRIC:
            log.info("Peer's NAT is syemmetric, punch may not be possible")

        punched = punch_udp_hole(
            sock, peer_addr, peer_ntfy_topic, peer_username, own_username
        )
        if not punched:
            log.error("Could not punch UDP hole")
            return

        log.info("connected!")

        for i in range(3):
            try:
                sock.send(f"Hello-{i} from {own_username}".encode("utf-8"))
                print(sock.recv(2048))
            except socket.timeout:
                log.info("socket timeout while exchanging hellos")
                continue

        me = NTFYPeerInfo(
            username=own_username,
            address=own_addr,
            nat=own_nat,
            topic=own_ntfy_topic,
        )
        peer = NTFYPeerInfo(
            username=peer_username,
            address=peer_addr,
            nat=own_nat,
            topic=own_ntfy_topic,
        )
        return Lynk(sock, me, peer)

    def __init__(self, sock: socket.socket, me: NTFYPeerInfo, peer: NTFYPeerInfo):
        self._sock = sock
        self._me = me
        self._peer = peer

    @property
    def udp_socket(self) -> socket.socket:
        return self._sock
