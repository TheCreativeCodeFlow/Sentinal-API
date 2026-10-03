import time
from collections import defaultdict
from typing import Dict, List, Tuple


class InMemoryRateLimiter:
    """Sliding-window in-memory rate limiter."""
    
    def __init__(self):
        # key -> list of timestamp floats
        self._requests: Dict[str, List[float]] = defaultdict(list)

    def is_allowed(
        self,
        key: str,
        limit: int = 60,
        window_seconds: int = 60
    ) -> Tuple[bool, int, int]:
        """
        Check if request is allowed under sliding window limit.
        Returns:
            (is_allowed: bool, remaining: int, retry_after_seconds: int)
        """
        now = time.time()
        window_start = now - window_seconds
        
        # Prune timestamps outside current window
        timestamps = [ts for ts in self._requests[key] if ts > window_start]
        self._requests[key] = timestamps

        if len(timestamps) >= limit:
            oldest = timestamps[0]
            retry_after = int(oldest + window_seconds - now) + 1
            return False, 0, max(1, retry_after)

        self._requests[key].append(now)
        remaining = limit - len(self._requests[key])
        return True, remaining, 0

    def reset(self):
        """Reset rate limiter state (useful for tests)."""
        self._requests.clear()


rate_limiter = InMemoryRateLimiter()
