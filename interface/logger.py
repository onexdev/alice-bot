"""
Interface Logger Module untuk ALICE Bot - Enterprise Logging System
Sistem logging komprehensif dengan rotation, filtering, dan audit trail.

Modul ini menangani:

- Multi-level logging dengan severity classification
- Automatic log rotation dengan size dan time-based triggers
- Structured logging dengan JSON format untuk analysis
- Performance metrics logging dengan real-time monitoring
- Security audit logging untuk compliance
- Error tracking dengan stack trace preservation
- Memory-efficient logging dengan async I/O
- Log file compression untuk storage optimization

Penulis: onex_dv
GitHub: https://github.com/onexdev
Lisensi: MIT Professional
Versi: 1.0.0
"""

import logging
import logging.handlers
import json
import os
import sys
import traceback
import time
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, Union
import gzip
import shutil
from concurrent.futures import ThreadPoolExecutor

class StructuredFormatter(logging.Formatter):
    """
    Custom formatter untuk structured logging dengan JSON output.
    Mengkonversi log records ke format JSON yang mudah dianalysis.
    """

    def __init__(self, include_extra: bool = True):
        super().__init__()
        self.include_extra = include_extra
        self.base_fields = {
            'timestamp', 'level', 'logger', 'message', 'module',
            'function', 'line', 'thread', 'process'
        }

    def format(self, record: logging.LogRecord) -> str:
        try:
            log_entry = {
                'timestamp': datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
                'level': record.levelname,
                'logger': record.name,
                'message': record.getMessage(),
                'module': record.module,
                'function': record.funcName,
                'line': record.lineno,
                'thread': record.thread,
                'process': record.process,
                'thread_name': getattr(record, 'threadName', 'Unknown')
            }

            if record.exc_info:
                log_entry['exception'] = {
                    'type': record.exc_info[0].__name__ if record.exc_info[0] else None,
                    'message': str(record.exc_info[1]) if record.exc_info[1] else None,
                    'traceback': self.formatException(record.exc_info)
                }

            if self.include_extra:
                extra_fields = {}
                for key, value in record.__dict__.items():
                    if key not in self.base_fields and not key.startswith('_'):
                        try:
                            json.dumps(value)
                            extra_fields[key] = value
                        except (TypeError, ValueError):
                            extra_fields[key] = str(value)
                if extra_fields:
                    log_entry['extra'] = extra_fields

            return json.dumps(log_entry, ensure_ascii=False, separators=(',', ':'))

        except Exception as e:
            return f"LOG_FORMAT_ERROR: {record.getMessage()} | Error: {str(e)}"

class PerformanceFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if hasattr(record, 'performance_metric'):
            record.is_performance = True
        return True

class SecurityFilter(logging.Filter):
    def __init__(self):
        super().__init__()
        self.sensitive_patterns = [
            'password', 'token', 'key', 'secret', 'credential',
            'auth', 'login', 'session', 'private'
        ]

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage().lower()
        if any(pattern in message for pattern in self.sensitive_patterns):
            record.security_sensitive = True
            record.msg = self._mask_sensitive_data(record.msg)
        return True

    def _mask_sensitive_data(self, message: str) -> str:
        import re
        message = re.sub(r'\b[A-Za-z0-9]{20,}\b', '***MASKED***', message)
        message = re.sub(r'0x[a-fA-F0-9]{40}', '0x***MASKED***', message)
        return message

class CompressedTimedRotatingFileHandler(logging.handlers.TimedRotatingFileHandler):
    def __init__(self, filename: str, when: str = 'midnight', interval: int = 1,
                 backupCount: int = 7, compress: bool = True, **kwargs):
        super().__init__(filename, when, interval, backupCount, **kwargs)
        self.compress = compress
        self.thread_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="LogCompress")

    def doRollover(self):
        super().doRollover()
        if self.compress and self.backupCount > 0:
            self.thread_pool.submit(self._compress_old_logs)

    def _compress_old_logs(self):
        try:
            log_dir = Path(self.baseFilename).parent
            log_name = Path(self.baseFilename).stem
            for i in range(1, self.backupCount + 1):
                backup_file = log_dir / f"{log_name}.{i}"
                compressed_file = log_dir / f"{log_name}.{i}.gz"
                if backup_file.exists() and not compressed_file.exists():
                    with open(backup_file, 'rb') as f_in:
                        with gzip.open(compressed_file, 'wb') as f_out:
                            shutil.copyfileobj(f_in, f_out)
                    backup_file.unlink()
        except Exception:
            pass

class AliceLogger:
    def __init__(self, name: str = "alice_bot", log_level: str = "INFO"):
        self.name = name
        self.log_level = getattr(logging, log_level.upper(), logging.INFO)
        self.logger = logging.getLogger(name)
        self.logger.setLevel(self.log_level)
        if self.logger.handlers:
            self.logger.handlers.clear()
        self.log_dir = Path("logs")
        self.log_dir.mkdir(exist_ok=True, mode=0o755)
        self.metrics = {
            'logs_written': 0,
            'errors_logged': 0,
            'warnings_logged': 0,
            'start_time': time.time(),
            'last_log_time': 0
        }
        self._lock = threading.Lock()
        self._setup_console_handler()
        self._setup_file_handlers()
        self._setup_error_handler()
        self._setup_audit_handler()
        self.logger.info(f"Alice Logger initialized: level={log_level}, dir={self.log_dir}")

    def _setup_console_handler(self):
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_format = logging.Formatter(
            fmt='%(asctime)s [%(levelname)8s] %(name)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        console_handler.setFormatter(console_format)
        console_handler.addFilter(PerformanceFilter())
        self.logger.addHandler(console_handler)

    def _setup_file_handlers(self):
        main_log_file = self.log_dir / "alice_bot.log"
        main_handler = CompressedTimedRotatingFileHandler(
            filename=str(main_log_file),
            when='midnight',
            interval=1,
            backupCount=30,
            compress=True,
            encoding='utf-8'
        )
        main_handler.setLevel(logging.DEBUG)
        main_handler.setFormatter(StructuredFormatter(include_extra=True))
        main_handler.addFilter(SecurityFilter())
        self.logger.addHandler(main_handler)

        perf_log_file = self.log_dir / "performance.log"
        perf_handler = logging.handlers.RotatingFileHandler(
            filename=str(perf_log_file),
            maxBytes=10*1024*1024,
            backupCount=5,
            encoding='utf-8'
        )
        perf_handler.setLevel(logging.DEBUG)
        perf_handler.setFormatter(StructuredFormatter(include_extra=True))

        class PerformanceOnlyFilter(logging.Filter):
            def filter(self, record):
                return hasattr(record, 'performance_metric') or 'performance' in record.getMessage().lower()

        perf_handler.addFilter(PerformanceOnlyFilter())
        self.logger.addHandler(perf_handler)

    def _setup_error_handler(self):
        error_log_file = self.log_dir / "errors.log"
        error_handler = CompressedTimedRotatingFileHandler(
            filename=str(error_log_file),
            when='midnight',
            interval=1,
            backupCount=90,
            compress=True,
            encoding='utf-8'
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(StructuredFormatter(include_extra=True))
        self.logger.addHandler(error_handler)

    def _setup_audit_handler(self):
        audit_log_file = self.log_dir / "audit.log"
        audit_handler = CompressedTimedRotatingFileHandler(
            filename=str(audit_log_file),
            when='midnight',
            interval=1,
            backupCount=365,
            compress=True,
            encoding='utf-8'
        )
        audit_handler.setLevel(logging.INFO)
        audit_handler.setFormatter(StructuredFormatter(include_extra=True))

        class AuditFilter(logging.Filter):
            def filter(self, record):
                return (hasattr(record, 'audit') or
                        any(keyword in record.getMessage().lower()
                            for keyword in ['audit', 'security', 'access', 'auth']))

        audit_handler.addFilter(AuditFilter())
        self.logger.addHandler(audit_handler)

    def log_performance(self, metric_name: str, value: float, unit: str = "ms", **extra):
        with self._lock:
            self.metrics['logs_written'] += 1
            self.metrics['last_log_time'] = time.time()
        self.logger.info(
            f"Performance metric: {metric_name} = {value} {unit}",
            extra={
                'performance_metric': {
                    'name': metric_name,
                    'value': value,
                    'unit': unit,
                    'timestamp': time.time()
                },
                **extra
            }
        )

    def log_audit(self, action: str, user: str = "system", resource: str = "",
                  result: str = "success", **extra):
        self.logger.info(
            f"Audit: {action} by {user} on {resource} - {result}",
            extra={
                'audit': {
                    'action': action,
                    'user': user,
                    'resource': resource,
                    'result': result,
                    'timestamp': time.time()
                },
                **extra
            }
        )

    def log_error_with_context(self, error: Exception, context: Dict[str, Any] = None):
        with self._lock:
            self.metrics['errors_logged'] += 1
        context = context or {}
        self.logger.error(
            f"Error occurred: {type(error).__name__}: {str(error)}",
            exc_info=True,
            extra={
                'error_context': context,
                'error_type': type(error).__name__,
                'error_message': str(error)
            }
        )

    def log_api_call(self, endpoint: str, method: str, status_code: int,
                     response_time: float, **extra):
        level = logging.INFO if status_code < 400 else logging.ERROR
        self.logger.log(
            level,
            f"API Call: {method} {endpoint} - {status_code} ({response_time:.3f}s)",
            extra={
                'api_call': {
                    'endpoint': endpoint,
                    'method': method,
                    'status_code': status_code,
                    'response_time': response_time,
                    'timestamp': time.time()
                },
                'performance_metric': {
                    'name': 'api_response_time',
                    'value': response_time * 1000,
                    'unit': 'ms'
                },
                **extra
            }
        )

    def get_logger_stats(self) -> Dict[str, Any]:
        with self._lock:
            current_time = time.time()
            uptime = current_time - self.metrics['start_time']
            return {
                'uptime_seconds': uptime,
                'logs_written': self.metrics['logs_written'],
                'errors_logged': self.metrics['errors_logged'],
                'warnings_logged': self.metrics['warnings_logged'],
                'logs_per_second': self.metrics['logs_written'] / uptime if uptime > 0 else 0,
                'last_log_time': self.metrics['last_log_time'],
                'log_level': logging.getLevelName(self.log_level),
                'handlers_count': len(self.logger.handlers),
                'log_directory': str(self.log_dir)
            }

    def flush_logs(self):
        for handler in self.logger.handlers:
            if hasattr(handler, 'flush'):
                handler.flush()

    def close_logger(self):
        self.logger.info("Shutting down Alice Logger")
        self.flush_logs()
        for handler in self.logger.handlers[:]:
            handler.close()
            self.logger.removeHandler(handler)
        for handler in self.logger.handlers:
            if hasattr(handler, 'thread_pool'):
                handler.thread_pool.shutdown(wait=True)

_global_logger = None
_logger_lock = threading.Lock()

def setup_logger(name: str = "alice_bot", log_level: str = "INFO") -> AliceLogger:
    global _global_logger
    with _logger_lock:
        if _global_logger is None:
            _global_logger = AliceLogger(name, log_level)
        return _global_logger

def get_logger(name: str = "alice_bot") -> logging.Logger:
    if _global_logger is None:
        setup_logger(name)
    return logging.getLogger(name)

def cleanup_logger():
    global _global_logger
    with _logger_lock:
        if _global_logger:
            _global_logger.close_logger()
            _global_logger = None

if __name__ == "__main__":
    logger_system = setup_logger()
    logger = get_logger()

    logger.debug("Debug message untuk testing")
    logger.info("Info message untuk testing")
    logger.warning("Warning message untuk testing")
    logger.error("Error message untuk testing")

    logger_system.log_performance("test_operation", 150.5, "ms", operation="test")
    logger_system.log_audit("test_action", "test_user", "test_resource")

    logger_system.log_api_call("https://api.example.com/test", "GET", 200, 0.250)

    try:
        raise ValueError("Test error untuk logging")
    except Exception as e:
        logger_system.log_error_with_context(e, {"test_context": "value"})

    stats = logger_system.get_logger_stats()
    print(f"Logger stats: {json.dumps(stats, indent=2)}")

    cleanup_logger()
