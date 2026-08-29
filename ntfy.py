from __future__ import annotations

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


def ntfy_get_latest_peer(topic: str, expected_user: str) -> Optional[tuple[str, int]]:
    url = f"{NTFY_BASE}/{topic}/json?poll=1&since=latest"

    try:
        request = urllib.request.Request(url)

        with urllib.request.urlopen(request, timeout=10) as response:
            for line in response:
                try:
                    event = json.loads(line.decode())
                except json.JSONDecodeError:
                    continue

                if event.get("event") != "message":
                    continue

                try:
                    payload = json.loads(event.get("message", ""))

                    if payload.get("user") != expected_user:
                        continue

                    return str(payload["ip"]), int(payload["port"])

                except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                    continue

    except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
        log.warning("ntfy poll failed: %s", exc)

    return None
