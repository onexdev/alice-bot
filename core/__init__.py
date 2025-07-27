"""
ALICE Bot Core Package - Enterprise Blockchain Analysis Engine
Core module initialization dengan comprehensive component imports dan configuration.

Package ini berisi komponen inti untuk blockchain scanning, validation,
configuration management, dan utility functions dengan standar enterprise.

Penulis: onex_dv
GitHub: https://github.com/onexdev
Lisensi: MIT Professional
Versi: 1.0.0
"""

import logging
from typing import Optional, Dict, Any

# Core module version

version = "1.0.0"
package_name = "alice_bot.core"

# Import core components dengan error handling

try:
    from .scanner import ScannerJaringanBase
    from .config import ManagerKonfigurasi
    from .validator import ValidatorInput
    from .utils import (
        UtilityFunctions, TimestampFormatter, HashValidator,
        validate_transaction_hash, format_timestamp, get_system_metrics
    )
    from .exceptions import (
        AliceException, ValidationError, APIError, NetworkError,
        SecurityError, ConfigurationError, PerformanceError, FileSystemError,
        handle_exception_comprehensive, create_error_context
    )

    _core_imports_successful = True
    _core_import_error = None

except ImportError as e:
    _core_imports_successful = False
    _core_import_error = str(e)

    # Create fallback classes untuk graceful degradation
    class ScannerJaringanBase:
        def __init__(self, *args, **kwargs):
            raise ImportError(f"Scanner module not available: {_core_import_error}")

    class ManagerKonfigurasi:
        def __init__(self, *args, **kwargs):
            raise ImportError(f"Config module not available: {_core_import_error}")

    class ValidatorInput:
        def __init__(self, *args, **kwargs):
            raise ImportError(f"Validator module not available: {_core_import_error}")

    class UtilityFunctions:
        def __init__(self, *args, **kwargs):
            raise ImportError(f"Utils module not available: {_core_import_error}")

    class TimestampFormatter:
        def __init__(self, *args, **kwargs):
            raise ImportError(f"Utils module not available: {_core_import_error}")

    class HashValidator:
        def __init__(self, *args, **kwargs):
            raise ImportError(f"Utils module not available: {_core_import_error}")

    # Exception fallbacks
    AliceException = Exception
    ValidationError = ValueError
    APIError = ConnectionError
    NetworkError = ConnectionError
    SecurityError = RuntimeError
    ConfigurationError = RuntimeError
    PerformanceError = RuntimeError
    FileSystemError = OSError

    # Function fallbacks
    def validate_transaction_hash(tx_hash):
        raise ImportError(f"Utils module not available: {_core_import_error}")

    def format_timestamp(timestamp, format_type="age"):
        raise ImportError(f"Utils module not available: {_core_import_error}")

    def get_system_metrics():
        raise ImportError(f"Utils module not available: {_core_import_error}")

    def handle_exception_comprehensive(exception, logger=None, context=None):
        raise ImportError(f"Exception module not available: {_core_import_error}")

    def create_error_context(operation=None, user_input=None, system_state=None):
        raise ImportError(f"Exception module not available: {_core_import_error}")

def get_core_status() -> Dict[str, Any]:
    """Return status informasi untuk core package."""
    return {
        'package_name': package_name,
        'version': version,
        'imports_successful': _core_imports_successful,
        'import_error': _core_import_error,
        'available_components': [
            'ScannerJaringanBase',
            'ManagerKonfigurasi',
            'ValidatorInput',
            'UtilityFunctions',
            'TimestampFormatter',
            'HashValidator',
            'Exception Classes',
            'Utility Functions'
        ] if _core_imports_successful else []
    }

def create_core_scanner(api_key: str = None, logger: Optional[logging.Logger] = None):
    """
    Factory function untuk creating scanner instance dengan proper configuration.

    Args:
        api_key: API key untuk Etherscan API v2
        logger: Optional logger instance

    Returns:
        ScannerJaringanBase: Configured scanner instance

    Raises:
        ImportError: Jika core modules tidak tersedia
        ValueError: Jika API key tidak valid
    """
    if not _core_imports_successful:
        raise ImportError(f"Cannot create scanner: {_core_import_error}")
    if not api_key:
        api_key = "7YMQ2Y6QXZQ19IK47HWFHYIR261TVHNFNI"
    try:
        scanner = ScannerJaringanBase(api_key=api_key, logger=logger)
        return scanner
    except Exception as e:
        raise ValueError(f"Failed to create scanner: {str(e)}")

def create_config_manager(config_file: str = "config.ini", logger: Optional[logging.Logger] = None):
    """
    Factory function untuk creating configuration manager.

    Args:
        config_file: Path ke configuration file
        logger: Optional logger instance

    Returns:
        ManagerKonfigurasi: Configured config manager instance

    Raises:
        ImportError: Jika core modules tidak tersedia
    """
    if not _core_imports_successful:
        raise ImportError(f"Cannot create config manager: {_core_import_error}")
    try:
        config_manager = ManagerKonfigurasi(config_file=config_file, logger=logger)
        return config_manager
    except Exception as e:
        raise ValueError(f"Failed to create config manager: {str(e)}")

def create_input_validator(logger: Optional[logging.Logger] = None):
    """
    Factory function untuk creating input validator.

    Args:
        logger: Optional logger instance

    Returns:
        ValidatorInput: Configured validator instance

    Raises:
        ImportError: Jika core modules tidak tersedia
    """
    if not _core_imports_successful:
        raise ImportError(f"Cannot create validator: {_core_import_error}")
    try:
        validator = ValidatorInput(logger=logger)
        return validator
    except Exception as e:
        raise ValueError(f"Failed to create validator: {str(e)}")

def create_utility_functions(logger: Optional[logging.Logger] = None):
    """
    Factory function untuk creating utility functions instance.

    Args:
        logger: Optional logger instance

    Returns:
        UtilityFunctions: Configured utility functions instance

    Raises:
        ImportError: Jika core modules tidak tersedia
    """
    if not _core_imports_successful:
        raise ImportError(f"Cannot create utility functions: {_core_import_error}")
    try:
        utils = UtilityFunctions(logger=logger)
        return utils
    except Exception as e:
        raise ValueError(f"Failed to create utility functions: {str(e)}")

def validate_core_environment() -> Dict[str, Any]:
    """
    Validate core environment dan dependencies.

    Returns:
        Dict[str, Any]: Validation results dengan detailed information
    """
    validation_results = {
        'core_imports': _core_imports_successful,
        'import_error': _core_import_error,
        'required_modules': [
            'scanner', 'config', 'validator', 'utils', 'exceptions'
        ],
        'available_modules': [],
        'missing_modules': [],
        'validation_passed': False
    }
    if _core_imports_successful:
        module_checks = {
            'scanner': ScannerJaringanBase is not None,
            'config': ManagerKonfigurasi is not None,
            'validator': ValidatorInput is not None,
            'utils': UtilityFunctions is not None,
            'exceptions': AliceException is not None
        }
        for module_name, available in module_checks.items():
            if available:
                validation_results['available_modules'].append(module_name)
            else:
                validation_results['missing_modules'].append(module_name)
        validation_results['validation_passed'] = not validation_results['missing_modules']
    return validation_results

def get_core_configuration() -> Dict[str, Any]:
    """
    Get core package configuration information.

    Returns:
        Dict[str, Any]: Configuration information
    """
    return {
        'api_endpoint': 'https://api.etherscan.io/v2/api',
        'chain_id': '8453',
        'default_api_key_length': 34,
        'supported_output_formats': ['Vfull', 'Vfrom'],
        'max_memory_mb': 50,
        'target_execution_time_seconds': 1.0,
        'rate_limit_requests_per_second': 5,
        'encryption_algorithm': 'AES-256-GCM',
        'key_derivation_iterations': 100000,
        'supported_python_versions': ['3.8', '3.9', '3.10', '3.11', '3.12'],
        'supported_platforms': ['Windows', 'Linux', 'macOS']
    }

# Module exports

__all__ = [
    # Core classes
    'ScannerJaringanBase',
    'ManagerKonfigurasi',
    'ValidatorInput',
    'UtilityFunctions',
    'TimestampFormatter',
    'HashValidator',

    # Exception classes
    'AliceException',
    'ValidationError',
    'APIError',
    'NetworkError',
    'SecurityError',
    'ConfigurationError',
    'PerformanceError',
    'FileSystemError',

    # Utility functions
    'validate_transaction_hash',
    'format_timestamp',
    'get_system_metrics',
    'handle_exception_comprehensive',
    'create_error_context',

    # Factory functions
    'create_core_scanner',
    'create_config_manager',
    'create_input_validator',
    'create_utility_functions',

    # Information functions
    'get_core_status',
    'validate_core_environment',
    'get_core_configuration'
]

# Core package constants

CORE_VERSION = version
API_VERSION = "v2"
TARGET_CHAIN_ID = "8453"
DEFAULT_API_ENDPOINT = "https://api.etherscan.io/v2/api"
PERFORMANCE_TARGET_MS = 1000
MEMORY_LIMIT_MB = 50

# Package initialization logging

logger = logging.getLogger(__name__)

if _core_imports_successful:
    logger.info(f"ALICE Bot Core Package v{version} initialized successfully")
else:
    logger.error(f"ALICE Bot Core Package v{version} initialization failed: {_core_import_error}")
