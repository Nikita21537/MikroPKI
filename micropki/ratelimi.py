import time
from collections import defaultdict
from threading import Lock
from typing import Dict, Tuple, Optional
from datetime import datetime, timezone


class TokenBucket:


    def __init__(self, rate: float, burst: int):

        self.rate = rate
        self.burst = burst
        self.tokens = burst
        self.last_refill = time.monotonic()
        self._lock = Lock()

    def consume(self, tokens: int = 1) -> bool:

        with self._lock:
            now = time.monotonic()
            # Refill tokens based on elapsed time
            elapsed = now - self.last_refill
            refill_amount = elapsed * self.rate
            self.tokens = min(self.burst, self.tokens + refill_amount)
            self.last_refill = now

            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    def get_remaining_tokens(self) -> float:

        with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_refill
            refill_amount = elapsed * self.rate
            tokens = min(self.burst, self.tokens + refill_amount)
            return tokens


class RateLimiter:

    def __init__(self, rate: float, burst: int, cleanup_interval: int = 60):

        self.rate = rate
        self.burst = burst
        self.cleanup_interval = cleanup_interval
        self._buckets: Dict[str, TokenBucket] = {}
        self._lock = Lock()
        self._last_cleanup = time.monotonic()

    def _cleanup_idle_buckets(self) -> None:

        now = time.monotonic()
        if now - self._last_cleanup < self.cleanup_interval:
            return

        with self._lock:
            # Remove buckets older than 2x cleanup interval
            cutoff = now - (self.cleanup_interval * 2)
            to_remove = []
            # This is a simplification - in practice we'd track last access time
            if len(self._buckets) > 1000:
                # Clear half of the buckets if too many
                items = list(self._buckets.items())
                for client_id, _ in items[:len(items) // 2]:
                    to_remove.append(client_id)

            for client_id in to_remove:
                del self._buckets[client_id]

            self._last_cleanup = now

    def get_bucket(self, client_id: str) -> TokenBucket:

        with self._lock:
            if client_id not in self._buckets:
                self._buckets[client_id] = TokenBucket(self.rate, self.burst)
            return self._buckets[client_id]

    def allow_request(self, client_ip: str) -> Tuple[bool, float]:

        self._cleanup_idle_buckets()

        bucket = self.get_bucket(client_ip)
        allowed = bucket.consume()

        if not allowed:
            # Calculate retry after time
            remaining = bucket.get_remaining_tokens()
            retry_after = max(1.0, (1.0 - remaining) / self.rate) if self.rate > 0 else 1.0
            return False, retry_after

        return True, 0

    def get_stats(self, client_ip: str) -> Optional[Dict]:

        with self._lock:
            if client_ip not in self._buckets:
                return None
            bucket = self._buckets[client_ip]
            return {
                'tokens_remaining': bucket.get_remaining_tokens(),
                'rate': self.rate,
                'burst': self.burst
            }


class RateLimitMiddleware:

    def __init__(self, rate: float = 0, burst: int = 10):

        self.rate = rate
        self.burst = burst
        self._limiter = None
        if rate > 0:
            self._limiter = RateLimiter(rate, burst)

    def is_enabled(self) -> bool:

        return self._limiter is not None

    def check_request(self, client_ip: str) -> Tuple[bool, Optional[int]]:

        if not self._limiter:
            return True, None

        allowed, retry_after = self._limiter.allow_request(client_ip)
        return allowed, int(retry_after) if not allowed else None

    def get_limiter(self) -> Optional[RateLimiter]:

        return self._limiter



_global_rate_limiter: Optional[RateLimitMiddleware] = None


def init_rate_limiter(rate: float = 0, burst: int = 10) -> RateLimitMiddleware:

    global _global_rate_limiter
    _global_rate_limiter = RateLimitMiddleware(rate, burst)
    return _global_rate_limiter


def get_rate_limiter() -> Optional[RateLimitMiddleware]:

    return _global_rate_limiter