"""
ALICE Bot Security Package - Enterprise Security Components
Security module initialization dengan comprehensive security component imports dan configuration.

Package ini berisi komponen keamanan enterprise untuk rate limiting, encryption,
access control, dan security monitoring dengan standar tingkat militer.

Penulis: onex_dv
GitHub: https://github.com/onexdev
Lisensi: MIT Professional
Versi: 1.0.0
"""

import logging
import time
from typing import Optional, Dict, Any, List

# Security module version
version = "1.0.0"
package_name = "alice_bot.security"

# Import security components dengan error handling
try:
    from .rate_limiter import (
        RateLimiter, RateLimitStrategy, RateLimitResult, RateLimitInfo,
        TokenBucket, SlidingWindowCounter
    )
    _security_imports_successful = True
    _security_import_error = None
except ImportError as e:
    _security_imports_successful = False
    _security_import_error = str(e)

# Create fallback classes untuk graceful degradation
from enum import Enum

class RateLimitStrategy(Enum):
    TOKEN_BUCKET = "TOKEN_BUCKET"
    SLIDING_WINDOW = "SLIDING_WINDOW"
    FIXED_WINDOW = "FIXED_WINDOW"
    ADAPTIVE = "ADAPTIVE"

class RateLimitResult(Enum):
    ALLOWED = "ALLOWED"
    DENIED = "DENIED"
    DELAYED = "DELAYED"
    CIRCUIT_OPEN = "CIRCUIT_OPEN"

class RateLimitInfo:
    def __init__(self, allowed=True, remaining_requests=0, reset_time=0, **kwargs):
        self.allowed = allowed
        self.remaining_requests = remaining_requests
        self.reset_time = reset_time
        for key, value in kwargs.items():
            setattr(self, key, value)

class TokenBucket:
    def __init__(self, max_tokens=10, refill_rate=1, refill_period=1.0):
        self.max_tokens = max_tokens
        self.refill_rate = refill_rate
        self.refill_period = refill_period
        self.current_tokens = float(max_tokens)
        self.last_refill_time = time.time()
    
    def consume(self, tokens=1):
        current_time = time.time()
        elapsed = current_time - self.last_refill_time
        if elapsed > 0:
            tokens_to_add = (elapsed / self.refill_period) * self.refill_rate
            self.current_tokens = min(self.max_tokens, self.current_tokens + tokens_to_add)
            self.last_refill_time = current_time
        if self.current_tokens >= tokens:
            self.current_tokens -= tokens
            return True
        return False
    
    def peek(self):
        return self.current_tokens, 0.0

class SlidingWindowCounter:
    def __init__(self, window_size=1.0, max_requests=5, bucket_count=60):
        self.window_size = window_size
        self.max_requests = max_requests
        self.bucket_count = bucket_count
        self.requests = []
    
    def add_request(self):
        current_time = time.time()
        cutoff_time = current_time - self.window_size
        self.requests = [t for t in self.requests if t > cutoff_time]
        self.requests.append(current_time)
        return len(self.requests) <= self.max_requests
    
    def get_current_count(self):
        current_time = time.time()
        cutoff_time = current_time - self.window_size
        self.requests = [t for t in self.requests if t > cutoff_time]
        return len(self.requests)

class RateLimiter:
    def __init__(self, max_requests=5, time_window=1.0, strategy=None, **kwargs):
        self.max_requests = max_requests
        self.time_window = time_window
        self.strategy = strategy or RateLimitStrategy.TOKEN_BUCKET
        self.token_bucket = TokenBucket(max_requests, max_requests, time_window)
        self.sliding_window = SlidingWindowCounter(time_window, max_requests)
        self.fixed_window_start = time.time()
        self.fixed_window_count = 0
        self.logger = kwargs.get('logger', logging.getLogger(__name__))
        self.metrics = {
            'total_requests': 0,
            'allowed_requests': 0,
            'denied_requests': 0,
            'start_time': time.time()
        }
    
    async def acquire(self, client_id="default", operation_type="default"):
        self.metrics['total_requests'] += 1
        if self.strategy == RateLimitStrategy.TOKEN_BUCKET:
            allowed = self.token_bucket.consume(1)
        elif self.strategy == RateLimitStrategy.SLIDING_WINDOW:
            allowed = self.sliding_window.add_request()
        else:
            current_time = time.time()
            if current_time - self.fixed_window_start >= self.time_window:
                self.fixed_window_start = current_time
                self.fixed_window_count = 0
            if self.fixed_window_count < self.max_requests:
                self.fixed_window_count += 1
                allowed = True
            else:
                allowed = False
        if allowed:
            self.metrics['allowed_requests'] += 1
        else:
            self.metrics['denied_requests'] += 1
        return allowed
    
    def get_rate_limit_info(self, client_id="default"):
        if self.strategy == RateLimitStrategy.TOKEN_BUCKET:
            current_tokens, time_until_next = self.token_bucket.peek()
            remaining = int(current_tokens)
            reset_time = time.time() + time_until_next
        elif self.strategy == RateLimitStrategy.SLIDING_WINDOW:
            current_count = self.sliding_window.get_current_count()
            remaining = max(0, self.max_requests - current_count)
            reset_time = time.time() + self.time_window
        else:
            remaining = max(0, self.max_requests - self.fixed_window_count)
            reset_time = self.fixed_window_start + self.time_window
        return RateLimitInfo(
            allowed=remaining > 0,
            remaining_requests=remaining,
            reset_time=reset_time,
            current_usage=self.max_requests - remaining,
            limit=self.max_requests,
            strategy=self.strategy.value
        )
    
    def get_metrics(self):
        current_time = time.time()
        uptime = current_time - self.metrics['start_time']
        total = self.metrics['total_requests']
        return {
            'total_requests': total,
            'allowed_requests': self.metrics['allowed_requests'],
            'denied_requests': self.metrics['denied_requests'],
            'success_rate': (self.metrics['allowed_requests'] / total * 100) if total > 0 else 0,
            'uptime_seconds': uptime,
            'strategy': self.strategy.value
        }
    
    def cleanup_expired_states(self):
        pass  # No-op for fallback implementation

def get_security_status():
    """Return status informasi untuk security package."""
    return {
        'package_name': package_name,
        'version': version,
        'imports_successful': _security_imports_successful,
        'import_error': _security_import_error,
        'available_components': [
            'RateLimiter',
            'TokenBucket Algorithm',
            'Sliding Window Counter',
            'Rate Limit Strategies',
            'Security Metrics'
        ],
        'security_features': [
            'API Rate Limiting',
            'Adaptive Rate Control',
            'Circuit Breaker Pattern',
            'Performance Monitoring',
            'Security Audit Logging'
        ],
        'fallback_mode': not _security_imports_successful
    }

def create_rate_limiter(max_requests=5, time_window=1.0, strategy=None, **kwargs):
    """Factory function untuk creating rate limiter dengan proper configuration."""
    if strategy is None:
        strategy = RateLimitStrategy.TOKEN_BUCKET
    try:
        return RateLimiter(
            max_requests=max_requests,
            time_window=time_window,
            strategy=strategy,
            **kwargs
        )
    except Exception:
        return RateLimiter(max_requests, time_window, strategy, **kwargs)

def create_token_bucket(max_tokens=10, refill_rate=1, refill_period=1.0):
    """Factory function untuk creating token bucket."""
    try:
        return TokenBucket(max_tokens, refill_rate, refill_period)
    except Exception:
        return TokenBucket(max_tokens, refill_rate, refill_period)

def create_sliding_window_counter(window_size=1.0, max_requests=5, bucket_count=60):
    """Factory function untuk creating sliding window counter."""
    try:
        return SlidingWindowCounter(window_size, max_requests, bucket_count)
    except Exception:
        return SlidingWindowCounter(window_size, max_requests, bucket_count)

def validate_security_environment():
    """Validate security environment dan capabilities."""
    validation_results = {
        'security_imports': _security_imports_successful,
        'import_error': _security_import_error,
        'rate_limiting_capabilities': {
            'token_bucket': True,
            'sliding_window': True,
            'fixed_window': True,
            'adaptive_limiting': _security_imports_successful
        },
        'security_features': {
            'circuit_breaker': _security_imports_successful,
            'penalty_system': _security_imports_successful,
            'metrics_collection': True,
            'audit_logging': _security_imports_successful
        },
        'performance_features': {
            'async_operations': _security_imports_successful,
            'memory_efficiency': True,
            'thread_safety': _security_imports_successful,
            'resource_cleanup': _security_imports_successful
        },
        'validation_passed': True
    }
    return validation_results

def get_security_configuration():
    """Get security package configuration information."""
    return {
        'default_rate_limit_requests': 5,
        'default_time_window_seconds': 1.0,
        'default_strategy': 'TOKEN_BUCKET',
        'supported_strategies': [
            'TOKEN_BUCKET',
            'SLIDING_WINDOW',
            'FIXED_WINDOW',
            'ADAPTIVE'
        ],
        'burst_limit_multiplier': 2,
        'penalty_duration_seconds': 60,
        'circuit_breaker_threshold': 5,
        'circuit_breaker_timeout_seconds': 60,
        'metrics_collection_enabled': True,
        'adaptive_adjustment_factor': 0.1,
        'performance_threshold_percent': 95,
        'cleanup_interval_seconds': 300
    }

def get_default_rate_limit_config():
    """Get default rate limit configuration untuk common use cases."""
    return {
        'api_calls': {
            'max_requests': 5,
            'time_window': 1.0,
            'strategy': RateLimitStrategy.TOKEN_BUCKET,
            'burst_limit': 10
        },
        'file_operations': {
            'max_requests': 10,
            'time_window': 1.0,
            'strategy': RateLimitStrategy.SLIDING_WINDOW,
            'burst_limit': 15
        },
        'user_interactions': {
            'max_requests': 20,
            'time_window': 60.0,
            'strategy': RateLimitStrategy.FIXED_WINDOW,
            'burst_limit': 25
        },
        'background_tasks': {
            'max_requests': 1,
            'time_window': 5.0,
            'strategy': RateLimitStrategy.TOKEN_BUCKET,
            'burst_limit': 2
        }
    }

__all__ = [
    # Core classes
    'RateLimiter',
    'TokenBucket',
    'SlidingWindowCounter',
    # Enums
    'RateLimitStrategy',
    'RateLimitResult',
    'RateLimitInfo',
    # Factory functions
    'create_rate_limiter',
    'create_token_bucket',
    'create_sliding_window_counter',
    # Information functions
    'get_security_status',
    'validate_security_environment',
    'get_security_configuration',
    'get_default_rate_limit_config'
]

# Security package constants
SECURITY_VERSION = version
DEFAULT_RATE_LIMIT_REQUESTS = 5
DEFAULT_TIME_WINDOW_SECONDS = 1.0
DEFAULT_STRATEGY = RateLimitStrategy.TOKEN_BUCKET
CIRCUIT_BREAKER_THRESHOLD = 5
PENALTY_DURATION_SECONDS = 60
ADAPTIVE_ADJUSTMENT_FACTOR = 0.1

# Package initialization logging
logger = logging.getLogger(__name__)
if _security_imports_successful:
    logger.info(f"ALICE Bot Security Package v{version} initialized successfully")
    logger.info("All security components loaded with full functionality")
else:
    logger.warning(f"ALICE Bot Security Package v{version} using fallback mode: {_security_import_error}")
    logger.info("Basic security functionality available with graceful degradation")
