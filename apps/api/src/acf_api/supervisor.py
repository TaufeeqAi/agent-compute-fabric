"""Telling the service manager what state a process is in.

A process started by systemd with ``Type=notify`` is given the address of a datagram socket in
``NOTIFY_SOCKET``. One datagram with ``READY=1`` says that the process serves; units ordered after it
are started only then. Without that variable every function here does nothing, so the same program runs
unchanged in a terminal, in a container and in a test.

The protocol is a few lines, which is why there is no dependency for it:
https://www.freedesktop.org/software/systemd/man/latest/sd_notify.html
"""

from __future__ import annotations

import contextlib
import os
import socket
from typing import Final

_VARIABLE: Final = "NOTIFY_SOCKET"
_STATUS_MAX: Final = 200


def _send(state: str) -> bool:
    address = os.environ.get(_VARIABLE, "")
    if not address or address[0] not in "/@":
        return False
    # A leading `@` names a socket in the abstract namespace, which the kernel spells with a zero byte.
    target = "\0" + address[1:] if address[0] == "@" else address
    with contextlib.suppress(OSError), socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM | socket.SOCK_CLOEXEC) as sock:
        sock.sendto(state.encode("utf-8"), target)
        return True
    return False


def _status(text: str) -> str:
    """One line a person reads in ``systemctl status``. Never a secret: callers pass ids and counts only."""
    return " ".join(text.split())[:_STATUS_MAX]


def ready(status: str = "") -> bool:
    """The process serves. Returns whether a service manager was told."""
    return _send("READY=1" + (f"\nSTATUS={_status(status)}" if status else ""))


def stopping(status: str = "draining") -> bool:
    """The process has begun to stop and takes no new work."""
    return _send(f"STOPPING=1\nSTATUS={_status(status)}")
