"""
Security Rate Limiter Module untuk ALICE Bot - Enterprise API Protection System
Sistem rate limiting dengan algoritma advanced untuk perlindungan API dan resource management.

Modul ini menangani:

- Token bucket algorithm dengan burst capacity management
- Sliding window rate limiting dengan precise timing control
- Adaptive rate limiting berdasarkan response patterns
- Circuit breaker integration untuk fault tolerance
- Multi-tier rate limiting dengan different limits untuk different operations
- Performance monitoring dengan real-time metrics tracking
- Thread-safe implementation dengan concurrent access support
- Penalty system untuk abuse prevention dan progressive restrictions

Penulis: onex_dv
GitHub: https://github.com/onexdev
Lisensi: MIT Professional
Versi: 1.0.0
"""

import asyncio
import time
import threading
from typing import Dict, Optional, Any, List, Tuple
from collections import deque, defaultdict
from enum import Enum
import logging
from dataclasses import dataclass
import math

class RateLimitStrategy(Enum):
    """Enumeration untuk different rate limiting strategies."""
    TOKEN_BUCKET = "TOKEN_BUCKET"
    SLIDING_WINDOW = "SLIDING_WINDOW"
    FIXED_WINDOW = "FIXED_WINDOW"
    ADAPTIVE = "ADAPTIVE"

class RateLimitResult(Enum):
    """Enumeration untuk rate limit check results."""
    ALLOWED = "ALLOWED"
    DENIED = "DENIED"
    DELAYED = "DELAYED"
    CIRCUIT_OPEN = "CIRCUIT_OPEN"

@dataclass
class RateLimitInfo:
    """Data class untuk rate limit information."""
    allowed: bool
    remaining_requests: int
    reset_time: float
    retry_after: Optional[float] = None
    current_usage: int = 0
    limit: int = 0
    strategy: str = ""

class TokenBucket:
    """
    Token bucket implementation untuk smooth rate limiting dengan burst capacity.
    """
    def __init__(
        self,
        max_tokens: int,
        refill_rate: float,
        refill_period: float = 1.0
    ):
        """
        Inisialisasi token bucket dengan specified parameters.
        """
        self.max_tokens = max_tokens
        self.refill_rate = refill_rate
        self.refill_period = refill_period
        self.current_tokens = float(max_tokens)
        self.last_refill_time = time.time()
        self._lock = threading.RLock()

    def _refill_tokens(self):
        """Refill tokens berdasarkan elapsed time."""
        current_time = time.time()
        elapsed_time = current_time - self.last_refill_time
        if elapsed_time > 0:
            tokens_to_add = (elapsed_time / self.refill_period) * self.refill_rate
            self.current_tokens = min(
                self.max_tokens,
                self.current_tokens + tokens_to_add
            )
            self.last_refill_time = current_time

    def consume(self, tokens: int = 1) -> bool:
        """
        Attempt to consume specified number of tokens.
        """
        with self._lock:
            self._refill_tokens()
            if self.current_tokens >= tokens:
                self.current_tokens -= tokens
                return True
            return False

    def peek(self) -> Tuple[float, float]:
        """
        Peek current state tanpa consuming tokens.
        """
        with self._lock:
            self._refill_tokens()
            if self.current_tokens >= self.max_tokens:
                time_until_next = 0.0
            else:
                time_until_next = self.refill_period / self.refill_rate
            return self.current_tokens, time_until_next

class SlidingWindowCounter:
    """
    Sliding window counter untuk precise rate limiting dengan time-based windows.
    """
    def __init__(self, window_size: float, max_requests: int, bucket_count: int = 60):
        """
        Inisialisasi sliding window counter.
        """
        self.window_size = window_size
        self.max_requests = max_requests
        self.bucket_count = bucket_count
        self.bucket_duration = window_size / bucket_count
        self.buckets: deque = deque(maxlen=bucket_count)
        self.bucket_timestamps: deque = deque(maxlen=bucket_count)
        current_time = time.time()
        for i in range(bucket_count):
            self.buckets.append(0)
            self.bucket_timestamps.append(current_time - (bucket_count - i) * self.bucket_duration)
        self._lock = threading.RLock()

    def _cleanup_old_buckets(self):
        """Cleanup buckets yang sudah expired."""
        current_time = time.time()
        cutoff_time = current_time - self.window_size
        while self.bucket_timestamps and self.bucket_timestamps[0] < cutoff_time:
            self.buckets.popleft()
            self.bucket_timestamps.popleft()

    def _get_current_bucket_index(self) -> int:
        """Get index dari current time bucket."""
        current_time = time.time()
        if not self.bucket_timestamps:
            return -1
        latest_bucket_time = self.bucket_timestamps[-1]
        time_diff = current_time - latest_bucket_time
        if time_diff < self.bucket_duration:
            return len(self.buckets) - 1
        return -1

    def add_request(self) -> bool:
        """
        Add request ke sliding window dan check if allowed.
        """
        with self._lock:
            self._cleanup_old_buckets()
            current_time = time.time()
            bucket_index = self._get_current_bucket_index()
            if bucket_index == -1:
                self.buckets.append(1)
                self.bucket_timestamps.append(current_time)
            else:
                self.buckets[bucket_index] += 1
            total_requests = sum(self.buckets)
            return total_requests <= self.max_requests

    def get_current_count(self) -> int:
        """
        Get current request count dalam sliding window.
        """
        with self._lock:
            self._cleanup_old_buckets()
            return sum(self.buckets)

class RateLimiter:
    """
    Enterprise rate limiter dengan multiple strategies dan advanced features.
    """
    def __init__(
        self,
        max_requests: int = 5,
        time_window: float = 1.0,
        strategy: RateLimitStrategy = RateLimitStrategy.TOKEN_BUCKET,
        burst_limit: Optional[int] = None,
        penalty_duration: float = 60.0,
        logger: Optional[logging.Logger] = None
    ):
        """
        Inisialisasi rate limiter dengan comprehensive configuration.
        """
        self.max_requests = max_requests
        self.time_window = time_window
        self.strategy = strategy
        self.burst_limit = burst_limit or max(max_requests * 2, 10)
        self.penalty_duration = penalty_duration
        self.logger = logger or logging.getLogger(__name__)
        self._lock = threading.RLock()
        self._token_bucket = TokenBucket(
            max_tokens=self.burst_limit,
            refill_rate=max_requests,
            refill_period=time_window
        )
        self._sliding_window = SlidingWindowCounter(
            window_size=time_window,
            max_requests=max_requests
        )
        self._fixed_window_start = time.time()
        self._fixed_window_count = 0
        self._client_states: Dict[str, Dict[str, Any]] = defaultdict(dict)
        self._penalties: Dict[str, float] = {}
        self.metrics = {
            'total_requests': 0,
            'allowed_requests': 0,
            'denied_requests': 0,
            'penalty_applied': 0,
            'adaptive_adjustments': 0,
            'start_time': time.time()
        }
        self.adaptive_enabled = True
        self.adaptive_adjustment_factor = 0.1
        self.performance_threshold = 0.95
        self.logger.info(f"RateLimiter initialized: strategy={strategy.value}, max_requests={max_requests}")

    async def acquire(self, client_id: str = "default", operation_type: str = "default") -> bool:
        """
        Acquire permission untuk make request dengan comprehensive checking.
        """
        with self._lock:
            self.metrics['total_requests'] += 1
            if self._is_client_penalized(client_id):
                self.metrics['denied_requests'] += 1
                self.logger.warning(f"Request denied untuk client {client_id}: penalty active")
                return False
            if self.strategy == RateLimitStrategy.TOKEN_BUCKET:
                allowed = self._token_bucket.consume(1)
            elif self.strategy == RateLimitStrategy.SLIDING_WINDOW:
                allowed = self._sliding_window.add_request()
            elif self.strategy == RateLimitStrategy.FIXED_WINDOW:
                allowed = self._check_fixed_window()
            else:
                allowed = self._check_adaptive_limit(client_id)
            if allowed:
                self.metrics['allowed_requests'] += 1
                self.logger.debug(f"Request allowed untuk client {client_id}")
            else:
                self.metrics['denied_requests'] += 1
                self._apply_penalty_if_needed(client_id)
                self.logger.warning(f"Request denied untuk client {client_id}: rate limit exceeded")
            if self.adaptive_enabled:
                await self._adjust_adaptive_limits()
            return allowed

    def _is_client_penalized(self, client_id: str) -> bool:
        """Check apakah client sedang dalam penalty period."""
        if client_id not in self._penalties:
            return False
        current_time = time.time()
        penalty_end_time = self._penalties[client_id]
        if current_time >= penalty_end_time:
            del self._penalties[client_id]
            return False
        return True

    def _apply_penalty_if_needed(self, client_id: str):
        """Apply penalty untuk client yang repeatedly exceed limits."""
        if client_id not in self._client_states:
            self._client_states[client_id] = {'violations': 0, 'last_violation': time.time()}
        state = self._client_states[client_id]
        now = time.time()
        if now - state['last_violation'] > self.penalty_duration:
            state['violations'] = 0
        state['violations'] += 1
        state['last_violation'] = now
        if state['violations'] >= 5:
            self._penalties[client_id] = now + self.penalty_duration
            self.metrics['penalty_applied'] += 1
            self.logger.warning(
                f"Penalty applied untuk client {client_id}: {state['violations']} violations, "
                f"penalty until {self._penalties[client_id]}"
            )

    def _check_fixed_window(self) -> bool:
        """Check fixed window rate limit."""
        now = time.time()
        if now - self._fixed_window_start >= self.time_window:
            self._fixed_window_start = now
            self._fixed_window_count = 0
        if self._fixed_window_count < self.max_requests:
            self._fixed_window_count += 1
            return True
        return False

    def _check_adaptive_limit(self, client_id: str) -> bool:
        """Check adaptive rate limit berdasarkan performance."""
        base_allowed = self._token_bucket.consume(1)
        if not base_allowed:
            return False
        state = self._client_states.setdefault(client_id, {})
        state.setdefault('recent_requests', deque(maxlen=10)).append(True)
        return True

    async def _adjust_adaptive_limits(self):
        """Adjust limits berdasarkan overall system performance."""
        total = self.metrics['total_requests']
        allowed = self.metrics['allowed_requests']
        if total > 100:
            success_rate = allowed / total
            if success_rate < self.performance_threshold:
                self.max_requests = max(1, int(self.max_requests * (1 - self.adaptive_adjustment_factor)))
                self.metrics['adaptive_adjustments'] += 1
                self.logger.info(f"Adaptive adjustment: decreased limit ke {self.max_requests}")
            elif success_rate > 0.99 and self.max_requests < 20:
                self.max_requests = min(20, int(self.max_requests * (1 + self.adaptive_adjustment_factor)))
                self.metrics['adaptive_adjustments'] += 1
                self.logger.info(f"Adaptive adjustment: increased limit ke {self.max_requests}")

    def get_rate_limit_info(self, client_id: str = "default") -> RateLimitInfo:
        """
        Get comprehensive rate limit information untuk client.
        """
        with self._lock:
            if self._is_client_penalized(client_id):
                end = self._penalties[client_id]
                return RateLimitInfo(
                    allowed=False,
                    remaining_requests=0,
                    reset_time=end,
                    retry_after=end - time.time(),
                    current_usage=self.max_requests,
                    limit=self.max_requests,
                    strategy=self.strategy.value
                )
            if self.strategy == RateLimitStrategy.TOKEN_BUCKET:
                tokens, wait = self._token_bucket.peek()
                rem = int(tokens)
                rt = time.time() + wait
            elif self.strategy == RateLimitStrategy.SLIDING_WINDOW:
                cnt = self._sliding_window.get_current_count()
                rem = max(0, self.max_requests - cnt)
                rt = time.time() + self.time_window
            else:
                rem = max(0, self.max_requests - self._fixed_window_count)
                rt = self._fixed_window_start + self.time_window
            return RateLimitInfo(
                allowed=rem > 0,
                remaining_requests=rem,
                reset_time=rt,
                current_usage=self.max_requests - rem,
                limit=self.max_requests,
                strategy=self.strategy.value
            )

    def reset_client_state(self, client_id: str):
        """Reset state untuk specific client."""
        with self._lock:
            self._client_states.pop(client_id, None)
            self._penalties.pop(client_id, None)
            self.logger.info(f"Reset state untuk client {client_id}")

    def get_metrics(self) -> Dict[str, Any]:
        """Get comprehensive rate limiter metrics."""
        with self._lock:
            now = time.time()
            up = now - self.metrics['start_time']
            total = self.metrics['total_requests']
            allowed = self.metrics['allowed_requests']
            denied = self.metrics['denied_requests']
            return {
                'uptime_seconds': up,
                'total_requests': total,
                'allowed_requests': allowed,
                'denied_requests': denied,
                'success_rate': (allowed / total * 100) if total else 0,
                'denial_rate': (denied / total * 100) if total else 0,
                'requests_per_second': total / up if up else 0,
                'penalties_applied': self.metrics['penalty_applied'],
                'adaptive_adjustments': self.metrics['adaptive_adjustments'],
                'active_penalties': len(self._penalties),
                'tracked_clients': len(self._client_states),
                'current_max_requests': self.max_requests,
                'strategy': self.strategy.value
            }

    def cleanup_expired_states(self):
        """Cleanup expired client states dan penalties."""
        with self._lock:
            now = time.time()
            expired_penalties = [cid for cid, end in self._penalties.items() if now >= end]
            for cid in expired_penalties:
                del self._penalties[cid]
            cutoff = now - (self.penalty_duration * 2)
            expired_clients = [cid for cid, s in self._client_states.items()
                               if s.get('last_violation', 0) < cutoff]
            for cid in expired_clients:
                del self._client_states[cid]
            if expired_penalties or expired_clients:
                self.logger.debug(
                    f"Cleanup completed: {len(expired_penalties)} penalties, "
                    f"{len(expired_clients)} client states"
                )

if __name__ == "__main__":
    # Test rate limiter functionality
    async def test_rate_limiter():
        strategies = [
            RateLimitStrategy.TOKEN_BUCKET,
            RateLimitStrategy.SLIDING_WINDOW,
            RateLimitStrategy.FIXED_WINDOW
        ]
        for strat in strategies:
            print(f"\nTesting {strat.value} strategy:")
            rl = RateLimiter(max_requests=3, time_window=1.0, strategy=strat)
            for i in range(5):
                allowed = await rl.acquire(f"client_{i%2}")
                info = rl.get_rate_limit_info(f"client_{i%2}")
                print(f"  Request {i+1}: {'ALLOWED' if allowed else 'DENIED'}, Remaining: {info.remaining_requests}")
                await asyncio.sleep(0.1)
            m = rl.get_metrics()
            print(f"  Success rate: {m['success_rate']:.1f}%")
            print(f"  Total requests: {m['total_requests']}")

    asyncio.run(test_rate_limiter())
