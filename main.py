from __future__ import annotations

import argparse
import logging
import socket
import sys

from ntfy import channel_for, ntfy_publish
from session import run_session
from stun import discover_public_endpoint

log = logging.getLogger("p2p")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--user", required=True)
    parser.add_argument("--peer")
    parser.add_argument(
        "--timeout",
        type=float,
        default=180.0,
        help="max seconds to wait for the initial connection; once connected the session runs until interrupted",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))

    log.info("UDP socket opened on local port %d", sock.getsockname()[1])

    try:
        endpoint, nat_type = discover_public_endpoint(sock)
        log.info("Public endpoint: %s:%d (%s)", endpoint.ip, endpoint.port, nat_type)

        my_topic = channel_for(args.user)
        ntfy_publish(my_topic, {"user": args.user, "ip": endpoint.ip, "port": endpoint.port, "nat_type": nat_type})

        peer_username = args.peer or input("Peer username: ").strip()

        if not peer_username:
            return 0

        peer_topic = channel_for(peer_username)

        success = run_session(
            sock=sock,
            username=args.user,
            my_topic=my_topic,
            peer_username=peer_username,
            peer_topic=peer_topic,
            initial_connect_timeout=args.timeout,
        )

        return 0 if success else 1

    except (RuntimeError, OSError) as exc:
        log.error("Failed: %s", exc)
        return 1

    except KeyboardInterrupt:
        log.info("Interrupted")
        return 0

    finally:
        sock.close()


if __name__ == "__main__":
    sys.exit(main())
