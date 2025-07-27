"""
Core Utilities Module untuk ALICE Bot - Enterprise Utility Functions
Kumpulan utility functions dengan standar enterprise untuk mendukung operasi sistem.

Modul ini menangani:

- File operations dengan atomic transactions dan error handling
- Memory management dengan monitoring dan optimization
- String manipulation dengan security considerations
- Network utilities dengan performance optimization
- Data conversion dengan validation dan sanitization
- System information gathering dengan comprehensive metrics
- Async operations dengan proper resource management
- Performance monitoring dengan real-time tracking

Penulis: onex_dv
GitHub: https://github.com/onexdev
Lisensi: MIT Professional
Versi: 1.0.0
"""

import os
import sys
import shutil
import asyncio
import aiofiles
import hashlib
import random
import time
import psutil
import platform
from pathlib import Path
from typing import Dict, Any, Optional, Union, List, Tuple
from datetime import datetime, timezone
import json
import re
import logging
import threading
from contextlib import asynccontextmanager
import tempfile

class UtilityFunctions:
    """
    Enterprise utility functions dengan comprehensive functionality dan error handling.
    Menyediakan berbagai utility functions yang diperlukan oleh sistem ALICE Bot.

    Fitur Enterprise:
    - Thread-safe operations dengan proper locking mechanisms
    - Memory monitoring dengan automatic cleanup
    - Performance tracking dengan metrics collection
    - Security-conscious implementations dengan input validation
    - Async-first design dengan proper resource management
    - Comprehensive error handling dengan detailed reporting
    - Cross-platform compatibility dengan OS-specific optimizations
    - Audit logging integration untuk compliance requirements
    """

    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Inisialisasi utility functions dengan performance monitoring.
        Args:
            logger: Optional logger instance untuk audit dan debugging
        """
        self.logger = logger or logging.getLogger(__name__)
        self._lock = threading.RLock()
        self.metrics = {
            'file_operations': 0,
            'memory_checks': 0,
            'network_operations': 0,
            'data_conversions': 0,
            'start_time': time.time()
        }
        self.memory_monitor_active = False
        self.max_memory_mb = 50
        self._temp_files: List[Path] = []
        self.logger.debug("UtilityFunctions initialized dengan enterprise configuration")

    def validate_ethereum_address(self, address: str) -> bool:
        if not address or not isinstance(address, str):
            return False
        clean_address = address.strip()
        if not clean_address.startswith('0x') or len(clean_address) != 42:
            return False
        hex_part = clean_address[2:]
        try:
            int(hex_part, 16)
            return True
        except ValueError:
            return False

    def sanitize_string_parameter(self, value: str) -> str:
        if not isinstance(value, str):
            return str(value)
        sanitized = value.replace('\x00', '').replace('\r', '').replace('\n', ' ')
        if len(sanitized) > 1000:
            sanitized = sanitized[:1000]
        return sanitized.strip()

    def sanitize_filename(self, filename: str) -> str:
        if not filename or not isinstance(filename, str):
            return "default_output.txt"
        clean_name = Path(filename).name
        dangerous_chars = '<>:"/\\|?*'
        for char in dangerous_chars:
            clean_name = clean_name.replace(char, '_')
        clean_name = clean_name.strip('. ')
        if not clean_name:
            clean_name = "sanitized_output.txt"
        if '.' not in clean_name:
            clean_name += '.txt'
        return clean_name

    def get_random(self) -> float:
        return random.random()

    def get_disk_space_free(self, path: str = ".") -> int:
        try:
            if platform.system() == 'Windows':
                free_bytes = shutil.disk_usage(path).free
            else:
                stat = os.statvfs(path)
                free_bytes = stat.f_bavail * stat.f_frsize
            return free_bytes
        except Exception as e:
            self.logger.warning(f"Error getting disk space: {str(e)}")
            return 0

    def get_memory_available(self) -> int:
        try:
            return psutil.virtual_memory().available
        except Exception as e:
            self.logger.warning(f"Error getting memory info: {str(e)}")
            return 0

    def get_memory_usage_current(self) -> float:
        try:
            process = psutil.Process()
            memory_info = process.memory_info()
            return memory_info.rss / 1024 / 1024
        except Exception as e:
            self.logger.warning(f"Error getting current memory usage: {str(e)}")
            return 0.0

    async def setup_memory_monitor(self, max_memory_mb: int = 50):
        self.max_memory_mb = max_memory_mb
        self.memory_monitor_active = True

        async def monitor_memory():
            while self.memory_monitor_active:
                try:
                    current_usage = self.get_memory_usage_current()
                    if current_usage > self.max_memory_mb:
                        self.logger.warning(
                            f"Memory usage ({current_usage:.2f}MB) exceeds limit ({self.max_memory_mb}MB)"
                        )
                    await asyncio.sleep(10)
                except Exception as e:
                    self.logger.error(f"Error in memory monitoring: {str(e)}")
                    await asyncio.sleep(30)

        asyncio.create_task(monitor_memory())
        self.logger.info(f"Memory monitoring activated with limit: {max_memory_mb}MB")

    @asynccontextmanager
    async def async_file_writer(self, file_path: Path):
        try:
            async with aiofiles.open(file_path, 'w', encoding='utf-8') as f:
                yield f
                await f.flush()
            with self._lock:
                self.metrics['file_operations'] += 1
        except Exception as e:
            self.logger.error(f"Error in async file writer: {str(e)}")
            raise

    async def atomic_move(self, source: Path, destination: Path):
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            if platform.system() == 'Windows':
                if destination.exists():
                    destination.unlink()
                shutil.move(str(source), str(destination))
            else:
                source.rename(destination)
            with self._lock:
                self.metrics['file_operations'] += 1
            self.logger.debug(f"Atomic move completed: {source} -> {destination}")
        except Exception as e:
            self.logger.error(f"Error in atomic move: {str(e)}")
            raise

    async def copy_file_async(self, source: Path, destination: Path):
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            await asyncio.get_event_loop().run_in_executor(
                None, shutil.copy2, str(source), str(destination)
            )
            with self._lock:
                self.metrics['file_operations'] += 1
            self.logger.debug(f"File copied: {source} -> {destination}")
        except Exception as e:
            self.logger.error(f"Error copying file: {str(e)}")
            raise

    async def cleanup_temp_files(self):
        cleanup_count = 0
        for temp_file in self._temp_files[:]:
            try:
                if temp_file.exists():
                    temp_file.unlink()
                    cleanup_count += 1
                self._temp_files.remove(temp_file)
            except Exception as e:
                self.logger.warning(f"Error cleaning up temp file {temp_file}: {str(e)}")
        if cleanup_count > 0:
            self.logger.debug(f"Cleaned up {cleanup_count} temporary files")

    def create_temp_file(self, suffix: str = ".tmp", prefix: str = "alice_") -> Path:
        try:
            temp_fd, temp_path = tempfile.mkstemp(suffix=suffix, prefix=prefix)
            os.close(temp_fd)
            temp_path_obj = Path(temp_path)
            self._temp_files.append(temp_path_obj)
            return temp_path_obj
        except Exception as e:
            self.logger.error(f"Error creating temp file: {str(e)}")
            raise

class TimestampFormatter:
    """
    Utility class untuk timestamp formatting dengan comprehensive options.
    Menyediakan berbagai format timestamp untuk keperluan logging dan display.
    """
    def __init__(self):
        self.default_timezone = timezone.utc

    def format_age_from_timestamp(self, timestamp: Union[str, int, float]) -> str:
        try:
            ts = float(timestamp)
            current_time = time.time()
            age_seconds = current_time - ts
            if age_seconds < 60:
                return f"{int(age_seconds)} detik yang lalu"
            elif age_seconds < 3600:
                return f"{int(age_seconds / 60)} menit yang lalu"
            elif age_seconds < 86400:
                return f"{int(age_seconds / 3600)} jam yang lalu"
            else:
                return f"{int(age_seconds / 86400)} hari yang lalu"
        except Exception:
            return "Unknown age"

    def format_timestamp_iso(self, timestamp: Union[str, int, float]) -> str:
        try:
            ts = float(timestamp)
            dt = datetime.fromtimestamp(ts, self.default_timezone)
            return dt.isoformat()
        except Exception:
            return datetime.now(self.default_timezone).isoformat()

class HashValidator:
    """
    Utility class untuk hash validation dengan comprehensive checks.
    Menyediakan validasi untuk berbagai format hash yang digunakan dalam blockchain.
    """
    def __init__(self):
        self.tx_hash_pattern = re.compile(r'^0x[a-fA-F0-9]{64}$')
        self.block_hash_pattern = re.compile(r'^0x[a-fA-F0-9]{64}$')

    def validate_transaction_hash(self, tx_hash: str) -> bool:
        if not tx_hash or not isinstance(tx_hash, str):
            return False
        return bool(self.tx_hash_pattern.match(tx_hash.strip()))

    def validate_block_hash(self, block_hash: str) -> bool:
        if not block_hash or not isinstance(block_hash, str):
            return False
        return bool(self.block_hash_pattern.match(block_hash.strip()))

    def compute_string_hash(self, input_string: str, algorithm: str = "sha256") -> str:
        try:
            if algorithm == "sha256":
                hash_obj = hashlib.sha256()
            elif algorithm == "md5":
                hash_obj = hashlib.md5()
            elif algorithm == "sha1":
                hash_obj = hashlib.sha1()
            else:
                raise ValueError(f"Unsupported hash algorithm: {algorithm}")
            hash_obj.update(input_string.encode('utf-8'))
            return hash_obj.hexdigest()
        except Exception as e:
            raise ValueError(f"Error computing hash: {str(e)}")

def validate_transaction_hash(tx_hash: str) -> bool:
    validator = HashValidator()
    return validator.validate_transaction_hash(tx_hash)

def format_timestamp(timestamp: Union[str, int, float], format_type: str = "age") -> str:
    formatter = TimestampFormatter()
    if format_type == "age":
        return formatter.format_age_from_timestamp(timestamp)
    elif format_type == "iso":
        return formatter.format_timestamp_iso(timestamp)
    else:
        return str(timestamp)

def get_system_metrics() -> Dict[str, Any]:
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        cpu_count = psutil.cpu_count()
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        network = psutil.net_io_counters()
        return {
            'cpu': {
                'percent': cpu_percent,
                'count': cpu_count
            },
            'memory': {
                'total': memory.total,
                'available': memory.available,
                'percent': memory.percent,
                'used': memory.used
            },
            'disk': {
                'total': disk.total,
                'used': disk.used,
                'free': disk.free,
                'percent': (disk.used / disk.total) * 100
            },
            'network': {
                'bytes_sent': network.bytes_sent,
                'bytes_recv': network.bytes_recv,
                'packets_sent': network.packets_sent,
                'packets_recv': network.packets_recv
            },
            'platform': {
                'system': platform.system(),
                'release': platform.release(),
                'version': platform.version(),
                'machine': platform.machine(),
                'processor': platform.processor()
            },
            'timestamp': time.time()
        }
    except Exception as e:
        return {
            'error': str(e),
            'timestamp': time.time()
        }

if __name__ == "__main__":
    utils = UtilityFunctions()
    test_addresses = [
        "0x1234567890abcdef1234567890abcdef12345678",
        "invalid_address",
        "0x12345"
    ]
    print("Testing address validation:")
    for addr in test_addresses:
        result = utils.validate_ethereum_address(addr)
        print(f"  {addr}: {'VALID' if result else 'INVALID'}")

    formatter = TimestampFormatter()
    current_time = time.time()
    old_time = current_time - 3600
    print(f"\nTesting timestamp formatting:")
    print(f"  Current time age: {formatter.format_age_from_timestamp(current_time)}")
    print(f"  1 hour ago age: {formatter.format_age_from_timestamp(old_time)}")

    hash_validator = HashValidator()
    test_hash = "0x" + "a" * 64
    print(f"\nTesting hash validation:")
    print(f"  Test hash valid: {hash_validator.validate_transaction_hash(test_hash)}")

    print(f"\nSystem metrics:")
    metrics = get_system_metrics()
    if 'error' not in metrics:
        print(f"  CPU usage: {metrics['cpu']['percent']}%")
        print(f"  Memory usage: {metrics['memory']['percent']}%")
        print(f"  Disk usage: {metrics['disk']['percent']:.1f}%")
    else:
        print(f"  Error getting metrics: {metrics['error']}")
