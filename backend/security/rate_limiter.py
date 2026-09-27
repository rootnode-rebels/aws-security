"""
Rate Limiter & Brute-Force Protection.
Enforces sliding-window request throttling and tracks failed attempt velocities.
"""
import time
import threading
from typing import Dict, List, Tuple

class RateLimiter:
    def __init__(self, max_attempts: int = 5, window_seconds: int = 600, lockout_seconds: int = 900, max_tracked: int = 10000):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self.max_tracked = max_tracked
        self.lock = threading.Lock()
        # Key: identifier (e.g. ip or email) -> list of failure timestamps
        self.failures: Dict[str, List[float]] = {}
        # Key: identifier -> lockout until timestamp
        self.lockouts: Dict[str, float] = {}

    def _prune_stale_records(self, now: float):
        """Purges expired lockouts and stale failure histories to prevent memory bloat."""
        # 1. Prune expired lockouts
        expired_lockouts = [k for k, until in self.lockouts.items() if now >= until]
        for k in expired_lockouts:
            del self.lockouts[k]

        # 2. Prune old failure records
        stale_keys = []
        for k, timestamps in self.failures.items():
            valid_ts = [t for t in timestamps if now - t < self.window_seconds]
            if valid_ts:
                self.failures[k] = valid_ts
            else:
                stale_keys.append(k)
        for k in stale_keys:
            del self.failures[k]

        # 3. If still exceeding max capacity, evict oldest entries (DoS protection)
        if len(self.failures) > self.max_tracked:
            # Sort by most recent failure timestamp and retain top half
            sorted_keys = sorted(self.failures.keys(), key=lambda k: max(self.failures[k]) if self.failures[k] else 0)
            to_remove = sorted_keys[:len(sorted_keys) - (self.max_tracked // 2)]
            for k in to_remove:
                del self.failures[k]

    def is_locked(self, identifier: str) -> Tuple[bool, int]:
        """Checks if identifier is currently locked out. Returns (is_locked, remaining_seconds)."""
        now = time.time()
        with self.lock:
            if identifier in self.lockouts:
                until = self.lockouts[identifier]
                if now < until:
                    return True, int(until - now)
                else:
                    del self.lockouts[identifier]
            return False, 0

    def record_failure(self, identifier: str) -> Tuple[bool, int]:
        """Records a failed attempt. If threshold exceeded, triggers lockout."""
        now = time.time()
        with self.lock:
            # Proactive pruning
            if len(self.failures) > self.max_tracked or len(self.lockouts) > self.max_tracked:
                self._prune_stale_records(now)

            history = self.failures.get(identifier, [])
            # Purge entries outside window
            history = [t for t in history if now - t < self.window_seconds]
            history.append(now)
            self.failures[identifier] = history

            if len(history) >= self.max_attempts:
                lockout_until = now + self.lockout_seconds
                self.lockouts[identifier] = lockout_until
                return True, self.lockout_seconds
            return False, 0

    def record_success(self, identifier: str):
        """Clears failure history on legitimate successful authentication."""
        with self.lock:
            self.failures.pop(identifier, None)
            self.lockouts.pop(identifier, None)

    def clear_all(self):
        """Resets all tracked failures and active lockouts."""
        with self.lock:
            self.failures.clear()
            self.lockouts.clear()

    def get_recent_failure_count(self, identifier: str, window_seconds: int = 900) -> int:
        """Returns the number of failures in the specified sliding window for ML feature extraction."""
        now = time.time()
        with self.lock:
            history = self.failures.get(identifier, [])
            return sum(1 for t in history if now - t < window_seconds)

rate_limiter = RateLimiter(max_attempts=5, window_seconds=600, lockout_seconds=900)
