from collections import deque

class BoundedSet:
    """Fixed-capacity set that evicts the oldest entry when full.
    Stores hashes only — does not hold references to the original items."""

    def __init__(self, maxlen):
        self._hashes = set()
        self._queue = deque(maxlen=maxlen)

    def add(self, item):
        h = hash(item)
        if h not in self._hashes:
            if len(self._queue) == self._queue.maxlen:
                self._hashes.discard(self._queue[0])  # evict oldest
            self._queue.append(h)
            self._hashes.add(h)

    def __contains__(self, item):
        return hash(item) in self._hashes

    def __len__(self):
        return len(self._hashes)
