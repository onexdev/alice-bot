# ================================================
# ALICE Bot - Advanced Legitimate Intelligence Crypto Explorer
# Main package initialization dengan comprehensive module imports dan configuration.
#
# Package ini menyediakan enterprise-grade blockchain scanning capabilities
# untuk Base network dengan tingkat keamanan militer dan performa sub-detik.
#
# Penulis: onex_dv
# GitHub: https://github.com/onexdev
# Lisensi: MIT Professional
# Versi: 1.0.0
# ================================================

import sys
import os
from pathlib import Path

# Package metadata
version = "1.0.0"
author = "onex_dv"
email = "onex@example.com"
license = "MIT"
description = "Advanced Legitimate Intelligence Crypto Explorer untuk Base Network"
url = "https://github.com/onexdev/alice-bot"

# Minimum Python version requirement
python_requires = ">=3.8.0"

# Add package root to Python path for proper imports
package_root = Path(__file__).parent
if str(package_root) not in sys.path:
    sys.path.insert(0, str(package_root))

# Version compatibility check
def check_python_version():
    """Verify Python version compatibility."""
    if sys.version_info < (3, 8):
        raise RuntimeError(
            f"ALICE Bot requires Python 3.8 or higher. "
            f"Current version: {sys.version_info.major}.{sys.version_info.minor}"
        )

# Perform version check on import
check_python_version()

# Core module imports dengan error handling
try:
    from .core.scanner import ScannerJaringanBase
    from .core.config import ManagerKonfigurasi
    from .core.validator import ValidatorInput
    from .core.exceptions import (
        AliceException, ValidationError, APIError, NetworkError,
        SecurityError, ConfigurationError, PerformanceError, FileSystemError
    )
    from .core.utils import UtilityFunctions, TimestampFormatter, HashValidator

    # Interface imports
    from .interface.banner import tampilkan_banner_selamat_datang, BannerDisplay
    from .interface.terminal import InterfaceTerminal
    from .interface.logger import setup_logger, get_logger, cleanup_logger

    # Security imports
    from .security.rate_limiter import RateLimiter, RateLimitStrategy, RateLimitResult

    _import_success = True
    _import_error = None

except ImportError as e:
    _import_success = False
    _import_error = str(e)

    # Fallback imports untuk graceful degradation
    ScannerJaringanBase = None
    ManagerKonfigurasi = None
    ValidatorInput = None
    AliceException = Exception  # Fallback to base Exception
    ValidationError = ValueError
    APIError = ConnectionError
    NetworkError = ConnectionError
    SecurityError = RuntimeError
    ConfigurationError = RuntimeError
    PerformanceError = RuntimeError
    FileSystemError = OSError
    UtilityFunctions = None
    TimestampFormatter = None
    HashValidator = None
    tampilkan_banner_selamat_datang = None
    BannerDisplay = None
    InterfaceTerminal = None
    setup_logger = None
    get_logger = None
    cleanup_logger = None
    RateLimiter = None
    RateLimitStrategy = None
    RateLimitResult = None

# ================================================
# Package-level constants
# ================================================

API_VERSION = "v2"
TARGET_CHAIN_ID = "8453"  # Base network
API_ENDPOINT = "https://api.etherscan.io/v2/api"
DEFAULT_API_KEY = "7YMQ2Y6QXZQ19IK47HWFHYIR261TVHNFNI"

# Performance targets
PERFORMANCE_TARGET_SECONDS = 1.0
MEMORY_LIMIT_MB = 50
RATE_LIMIT_REQUESTS_PER_SECOND = 5

# Security configuration
SECURITY_LEVEL = "ENTERPRISE"
ENCRYPTION_ALGORITHM = "AES-256-GCM"
KEY_DERIVATION_ITERATIONS = 100000

# Logging configuration
DEFAULT_LOG_LEVEL = "INFO"
LOG_ROTATION = "daily"
LOG_RETENTION_DAYS = 30

# ================================================
# Utility functions
# ================================================

def get_version():
    """Return package version string."""
    return version

def get_package_info():
    """Return comprehensive package information."""
    return {
        'name': 'alice-bot',
        'version': version,
        'author': author,
        'email': email,
        'license': license,
        'description': description,
        'url': url,
        'python_requires': python_requires,
        'api_version': API_VERSION,
        'target_chain_id': TARGET_CHAIN_ID,
        'api_endpoint': API_ENDPOINT,
        'security_level': SECURITY_LEVEL,
        'performance_target': PERFORMANCE_TARGET_SECONDS,
        'memory_limit_mb': MEMORY_LIMIT_MB,
        'import_success': _import_success,
        'import_error': _import_error
    }

def check_system_requirements():
    """Verify system requirements dan dependencies."""
    requirements_status = {
        'python_version': True,
        'dependencies': _import_success,
        'disk_space': True,
        'memory': True,
        'errors': []
    }

    # Check Python version
    if sys.version_info < (3, 8):
        requirements_status['python_version'] = False
        requirements_status['errors'].append(
            f"Python 3.8+ required, found {sys.version_info.major}.{sys.version_info.minor}"
        )

    # Check dependencies
    if not _import_success:
        requirements_status['dependencies'] = False
        requirements_status['errors'].append(f"Import error: {_import_error}")

    # Check disk space (minimum 100MB)
    try:
        import shutil
        free_space = shutil.disk_usage('.').free
        if free_space < 100 * 1024 * 1024:  # 100MB
            requirements_status['disk_space'] = False
            requirements_status['errors'].append(
                f"Insufficient disk space: {free_space // 1024 // 1024}MB available, 100MB required"
            )
    except Exception as e:
        requirements_status['errors'].append(f"Could not check disk space: {str(e)}")

    # Check available memory (minimum 128MB)
    try:
        import psutil
        available_memory = psutil.virtual_memory().available
        if available_memory < 128 * 1024 * 1024:  # 128MB
            requirements_status['memory'] = False
            requirements_status['errors'].append(
                f"Insufficient memory: {available_memory // 1024 // 1024}MB available, 128MB required"
            )
    except ImportError:
        requirements_status['errors'].append("psutil not available for memory check")
    except Exception as e:
        requirements_status['errors'].append(f"Could not check memory: {str(e)}")

    return requirements_status

def initialize_alice_bot():
    """Initialize ALICE Bot dengan comprehensive setup."""
    try:
        # Check system requirements
        req_status = check_system_requirements()

        if not all([req_status['python_version'], req_status['dependencies']]):
            error_msg = "ALICE Bot initialization failed:\n"
            for error in req_status['errors']:
                error_msg += f"  - {error}\n"
            raise RuntimeError(error_msg)

        # Create required directories
        directories = ['logs', 'result', 'backup', 'credentials', 'temp']
        for directory in directories:
            Path(directory).mkdir(exist_ok=True, mode=0o755)

        return True

    except Exception as e:
        raise RuntimeError(f"ALICE Bot initialization failed: {str(e)}")

def create_scanner_instance(api_key=None):
    """Create scanner instance dengan proper configuration."""
    if not _import_success:
        raise RuntimeError("Cannot create scanner: import failed")

    if not api_key:
        api_key = DEFAULT_API_KEY

    return ScannerJaringanBase(api_key=api_key)

def create_terminal_interface():
    """Create terminal interface instance."""
    if not _import_success:
        raise RuntimeError("Cannot create terminal interface: import failed")

    return InterfaceTerminal()

def setup_logging_system(log_level=None):
    """Setup logging system dengan default configuration."""
    if not _import_success:
        raise RuntimeError("Cannot setup logging: import failed")

    if not log_level:
        log_level = DEFAULT_LOG_LEVEL

    return setup_logger(log_level=log_level)

# ================================================
# Module exports untuk convenient access
# ================================================

__all__ = [
    # Core classes
    'ScannerJaringanBase',
    'ManagerKonfigurasi',
    'ValidatorInput',
    'UtilityFunctions',
    'TimestampFormatter',
    'HashValidator',

    # Interface classes
    'InterfaceTerminal',
    'BannerDisplay',

    # Security classes
    'RateLimiter',
    'RateLimitStrategy',
    'RateLimitResult',

    # Exception classes
    'AliceException',
    'ValidationError',
    'APIError',
    'NetworkError',
    'SecurityError',
    'ConfigurationError',
    'PerformanceError',
    'FileSystemError',

    # Functions
    'tampilkan_banner_selamat_datang',
    'setup_logger',
    'get_logger',
    'cleanup_logger',
    'get_version',
    'get_package_info',
    'check_system_requirements',
    'initialize_alice_bot',
    'create_scanner_instance',
    'create_terminal_interface',
    'setup_logging_system',

    # Constants
    'API_VERSION',
    'TARGET_CHAIN_ID',
    'API_ENDPOINT',
    'DEFAULT_API_KEY',
    'PERFORMANCE_TARGET_SECONDS',
    'MEMORY_LIMIT_MB',
    'RATE_LIMIT_REQUESTS_PER_SECOND',
    'SECURITY_LEVEL',
    'ENCRYPTION_ALGORITHM',
    'KEY_DERIVATION_ITERATIONS',
    'DEFAULT_LOG_LEVEL',
    'LOG_ROTATION',
    'LOG_RETENTION_DAYS'
]

# ================================================
# Deprecation warnings untuk future versions
# ================================================

import warnings

def deprecated_function_warning(old_name, new_name, version="2.0.0"):
    """Generate deprecation warning untuk function changes."""
    warnings.warn(
        f"{old_name} is deprecated and will be removed in version {version}. "
        f"Use {new_name} instead.",
        DeprecationWarning,
        stacklevel=2
    )

# ================================================
# Package initialization message
# ================================================

if _import_success:
    print(f"ALICE Bot v{version} - Enterprise Blockchain Scanner initialized successfully")
else:
    print(f"ALICE Bot v{version} - Warning: Some components failed to import")
    print(f"Import error: {_import_error}")
    print("Some functionality may be limited. Please check dependencies.")
