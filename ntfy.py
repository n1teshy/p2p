import hashlib
import json
import logging
import socket
import urllib.error
import urllib.request
from typing import Optional

log = logging.getLogger("p2p")

NTFY_BASE = "https://ntfy.sh"


def channel_for(username: str) -> str:
    digest = hashlib.sha256(username.strip().lower().encode()).hexdigest()
    return f"p2p-{digest[:16]}"


def ntfy_publish(topic: str, payload: dict, quiet: bool = False) -> None:
    url = f"{NTFY_BASE}/{topic}"

    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        method="POST",
        headers={"Content-Type": "application/json"},
    )

    with urllib.request.urlopen(request, timeout=10) as response:
        response.read()

    if not quiet:
        log.info("Published endpoint %s:%s", payload["ip"], payload["port"])


def ntfy_get_latest_peer(
    topic: str, expected_username: str
) -> Optional[tuple[str, int]]:
    url = f"{NTFY_BASE}/{topic}/json?poll=1&since=latest"

    try:
        request = urllib.request.Request(url)

        with urllib.request.urlopen(request, timeout=3) as response:
            for line in response:
                try:
                    message = json.loads(line.decode())["message"]
                    payload = json.loads(message)
                except json.JSONDecodeError:
                    continue

                try:
                    if payload.get("username") != expected_username:
                        continue

                    return str(payload["ip"]), int(payload["port"])

                except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                    continue

    except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
        log.warning("ntfy poll failed: %s", exc)

    return None
