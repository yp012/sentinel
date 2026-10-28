"""Bounded sliding-window primitives shared by the detectors.

Entries are ``(epoch_seconds, payload)`` tuples kept sorted by timestamp in a
``deque``. In-order arrival is an O(1) append and eviction is an O(1) amortized
``popleft``. Late (out-of-order) entries are placed with a binary search.
"""

from __future__ import annotations

from bisect import bisect_right
from collections import OrderedDict, deque
from datetime import datetime, timezone
from typing import Any, Deque, Hashable, Optional, Tuple

Entry = Tuple[float, Any]


class LRUDict(OrderedDict):
    """OrderedDict that drops the least recently written key once ``max_keys`` is hit."""

    def __init__(self, max_keys: int) -> None:
        super().__init__()
        self.max_keys = max_keys

    def __setitem__(self, key: Hashable, value: Any) -> None:
        if key in self:
            self.move_to_end(key)
        super().__setitem__(key, value)
        while len(self) > self.max_keys:
            self.popitem(last=False)


def insort_ts(dq: Deque[Entry], entry: Entry) -> None:
    """Insert ``entry`` keeping ``dq`` ordered by timestamp, respecting ``maxlen``."""
    if not dq or entry[0] >= dq[-1][0]:
        dq.append(entry)  # a full deque drops its oldest entry
        return
    if dq.maxlen is not None and len(dq) == dq.maxlen:
        if entry[0] < dq[0][0]:
            return  # older than everything we are allowed to keep
        dq.popleft()
    dq.insert(bisect_right(dq, entry[0], key=lambda e: e[0]), entry)


def evict_before(dq: Deque[Entry], cutoff: float) -> None:
    while dq and dq[0][0] < cutoff:
        dq.popleft()


class SlidingWindow:
    """Per-key time windows. The window is inclusive: ``[newest - window_s, newest]``."""

    def __init__(self, window_s: float, max_per_key: int, max_keys: int) -> None:
        self.window_s = window_s
        self.max_per_key = max_per_key
        self._keys: LRUDict = LRUDict(max_keys)

    def add(self, key: Hashable, ts: float, item: Any = None) -> Deque[Entry]:
        dq = self._keys.get(key)
        if dq is None:
            dq = deque(maxlen=self.max_per_key)
        self._keys[key] = dq  # also refreshes LRU position
        insort_ts(dq, (ts, item))
        evict_before(dq, dq[-1][0] - self.window_s)
        return dq

    def get(self, key: Hashable) -> Optional[Deque[Entry]]:
        return self._keys.get(key)

    def __len__(self) -> int:
        return len(self._keys)


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
