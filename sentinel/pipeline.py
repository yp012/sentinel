"""Ingestion pipeline (stub). For now only the live log follower lives here."""

from __future__ import annotations

import os
import threading
import time
from typing import Iterator, Optional

from sentinel.config import settings


def tail_file(
    path: str,
    *,
    from_start: bool = False,
    poll_interval: Optional[float] = None,
    stop_event: Optional[threading.Event] = None,
) -> Iterator[str]:
    """Follow ``path`` like ``tail -F`` using plain polling.

    Yields complete lines without the trailing newline. Survives the file not
    existing yet, truncation (``copytruncate``) and rotation (new inode). Returns
    once ``stop_event`` is set and no unread data remains.
    """
    interval = settings.tail_poll_interval_s if poll_interval is None else poll_interval
    stop = stop_event or threading.Event()
    fh = None
    inode = None
    buf = b""
    first_open = True

    try:
        while True:
            if fh is None:
                try:
                    fh = open(path, "rb")
                except FileNotFoundError:
                    if stop.is_set():
                        return
                    time.sleep(interval)
                    continue
                inode = os.fstat(fh.fileno()).st_ino
                if first_open and not from_start:
                    fh.seek(0, os.SEEK_END)
                first_open = False
                buf = b""

            chunk = fh.read()
            if chunk:
                buf += chunk
                *lines, buf = buf.split(b"\n")
                for ln in lines:
                    yield ln.rstrip(b"\r").decode("utf-8", errors="replace")
                continue

            # No new data: check for truncation or rotation before sleeping.
            try:
                st = os.stat(path)
            except FileNotFoundError:
                st = None
            if st is not None and st.st_ino != inode:
                fh.close()
                fh = None
                continue
            if st is not None and st.st_size < fh.tell():
                fh.seek(0)
                buf = b""
                continue

            if stop.is_set():
                return
            time.sleep(interval)
    finally:
        if fh is not None:
            fh.close()
