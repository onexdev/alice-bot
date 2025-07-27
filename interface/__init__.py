"""
ALICE Bot Interface Package - Professional User Interface Components
Interface module initialization dengan comprehensive UI component imports dan configuration.

Package ini berisi komponen interface untuk professional user interaction,
terminal display, logging system, dan banner presentation dengan standar enterprise.

Penulis: onex_dv
GitHub: https://github.com/onexdev
Lisensi: MIT Professional
Versi: 1.0.0
"""

import logging
import sys
from typing import Optional, Dict, Any

# Interface module version

version = "1.0.0"
package_name = "alice_bot.interface"

# Import interface components dengan error handling

try:
    from .banner import tampilkan_banner_selamat_datang, BannerDisplay
    from .terminal import InterfaceTerminal, ColorCode
    from .logger import (
        setup_logger, get_logger, cleanup_logger, AliceLogger,
        StructuredFormatter, PerformanceFilter, SecurityFilter,
        CompressedTimedRotatingFileHandler
    )

    _interface_imports_successful = True
    _interface_import_error = None

except ImportError as e:
    _interface_imports_successful = False
    _interface_import_error = str(e)

    # Create fallback classes untuk graceful degradation
    class BannerDisplay:
        def __init__(self, *args, **kwargs):
            raise ImportError(f"Banner module not available: {_interface_import_error}")

        def tampilkan_banner_utama(self):
            print("ALICE Bot - Enterprise Blockchain Scanner")

        def tampilkan_informasi_sistem(self):
            print("System information not available")

    class InterfaceTerminal:
        def __init__(self, *args, **kwargs):
            if _interface_import_error:
                print(f"Warning: Terminal interface limited - {_interface_import_error}")

        def print_success(self, message, bold=True):
            print(f"SUCCESS: {message}")

        def print_error(self, message, bold=True):
            print(f"ERROR: {message}")

        def print_warning(self, message, bold=False):
            print(f"WARNING: {message}")

        def print_info(self, message, bold=False):
            print(f"INFO: {message}")

        def print_step(self, message, bold=False):
            print(f"STEP: {message}")

        def konfirmasi_scan(self, wallet, versi, output_file):
            try:
                response = input(f"Scan {wallet} dengan format {versi}? (y/n): ")
                return response.lower() in ['y', 'yes', 'ya']
            except:
                return False

        def tampilkan_bantuan_lengkap(self):
            print("ALICE Bot Help:")
            print("  python alice.py sc <wallet> p <version> [file]")
            print("  python alice.py h")

    class AliceLogger:
        def __init__(self, *args, **kwargs):
            self.logger = logging.getLogger("alice_fallback")
            if not self.logger.handlers:
                handler = logging.StreamHandler()
                formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
                handler.setFormatter(formatter)
                self.logger.addHandler(handler)
                self.logger.setLevel(logging.INFO)

        def log_performance(self, metric_name, value, unit="ms", **extra):
            self.logger.info(f"Performance: {metric_name} = {value} {unit}")

        def log_audit(self, action, user="system", resource="", result="success", **extra):
            self.logger.info(f"Audit: {action} by {user} on {resource} - {result}")

        def log_error_with_context(self, error, context=None):
            self.logger.error(f"Error: {str(error)}")

        def get_logger_stats(self):
            return {'logs_written': 0, 'errors_logged': 0}

        def close_logger(self):
            pass

    class ColorCode:
        RESET = ''
        BOLD = ''
        GREEN = ''
        RED = ''
        YELLOW = ''
        BLUE = ''
        CYAN = ''
        MAGENTA = ''

    # Function fallbacks
    def tampilkan_banner_selamat_datang():
        print("=" * 80)
        print("ALICE Bot - Advanced Legitimate Intelligence Crypto Explorer")
        print("Enterprise Blockchain Scanner v1.0.0")
        print("=" * 80)

    def setup_logger(name="alice_bot", log_level="INFO"):
        return AliceLogger(name, log_level)

    def get_logger(name="alice_bot"):
        return logging.getLogger(name)

    def cleanup_logger():
        pass

    StructuredFormatter = logging.Formatter
    PerformanceFilter = logging.Filter
    SecurityFilter = logging.Filter
    CompressedTimedRotatingFileHandler = logging.handlers.TimedRotatingFileHandler

def get_interface_status():
    """Return status informasi untuk interface package."""
    return {
        'package_name': package_name,
        'version': version,
        'imports_successful': _interface_imports_successful,
        'import_error': _interface_import_error,
        'available_components': [
            'BannerDisplay',
            'InterfaceTerminal',
            'AliceLogger',
            'Logging Components',
            'Color Support'
        ] if _interface_imports_successful else ['Fallback Components'],
        'color_support': _check_color_support(),
        'unicode_support': _check_unicode_support()
    }

def _check_color_support():
    """Check apakah terminal mendukung colors."""
    try:
        return (
            hasattr(sys.stdout, 'isatty') and
            sys.stdout.isatty() and
            os.environ.get('TERM', '').lower() not in ['dumb', 'unknown']
        )
    except:
        return False

def _check_unicode_support():
    """Check apakah terminal mendukung Unicode."""
    try:
        return (
            sys.stdout.encoding and
            'utf' in sys.stdout.encoding.lower()
        )
    except:
        return False

def create_terminal_interface(enable_colors=None, logger=None):
    """
    Factory function untuk creating terminal interface dengan proper configuration.

    Args:
        enable_colors: Force enable/disable colors (None untuk auto-detect)
        logger: Optional logger instance

    Returns:
        InterfaceTerminal: Configured terminal interface instance

    Raises:
        ImportError: Jika interface modules tidak tersedia
    """
    if not _interface_imports_successful:
        return InterfaceTerminal()

    try:
        terminal = InterfaceTerminal(logger=logger, enable_colors=enable_colors)
        return terminal
    except Exception:
        return InterfaceTerminal()

def create_banner_display(logger=None):
    """
    Factory function untuk creating banner display.

    Args:
        logger: Optional logger instance

    Returns:
        BannerDisplay: Configured banner display instance
    """
    if not _interface_imports_successful:
        return BannerDisplay()

    try:
        banner = BannerDisplay(logger=logger)
        return banner
    except Exception:
        return BannerDisplay()

def create_logger_system(name="alice_bot", log_level="INFO"):
    """
    Factory function untuk creating logging system.

    Args:
        name: Logger name
        log_level: Logging level

    Returns:
        AliceLogger: Configured logging system instance
    """
    try:
        if _interface_imports_successful:
            logger_system = AliceLogger(name, log_level)
        else:
            logger_system = AliceLogger(name, log_level)
        return logger_system
    except Exception:
        return AliceLogger(name, log_level)

def display_welcome_banner():
    """Display welcome banner dengan proper fallback handling."""
    try:
        if _interface_imports_successful:
            tampilkan_banner_selamat_datang()
        else:
            print("=" * 80)
            print("ALICE Bot - Advanced Legitimate Intelligence Crypto Explorer")
            print("Enterprise Blockchain Scanner v1.0.0")
            print("Base Network Token Transfer Analysis")
            print("=" * 80)
            print("Author: onex_dv | GitHub: https://github.com/onexdev")
            print("=" * 80)
    except Exception as e:
        print("ALICE Bot - Enterprise Blockchain Scanner")
        print(f"Note: Full banner display not available - {str(e)}")

def validate_interface_environment():
    """Validate interface environment dan capabilities."""
    validation_results = {
        'interface_imports': _interface_imports_successful,
        'import_error': _interface_import_error,
        'terminal_capabilities': {
            'color_support': _check_color_support(),
            'unicode_support': _check_unicode_support(),
            'interactive': hasattr(sys.stdin, 'isatty') and sys.stdin.isatty()
        },
        'logging_capabilities': {
            'file_logging': True,
            'structured_logging': _interface_imports_successful,
            'log_rotation': _interface_imports_successful,
            'compression': _interface_imports_successful
        },
        'display_capabilities': {
            'banner_display': True,
            'progress_indication': _interface_imports_successful,
            'error_formatting': _interface_imports_successful
        },
        'validation_passed': True
    }
    return validation_results

def get_interface_configuration():
    """Get interface package configuration information."""
    return {
        'default_log_level': 'INFO',
        'log_rotation_policy': 'daily',
        'log_retention_days': 30,
        'max_log_file_size_mb': 10,
        'enable_log_compression': True,
        'enable_structured_logging': True,
        'enable_performance_logging': True,
        'enable_audit_logging': True,
        'terminal_width_default': 80,
        'color_scheme': 'enterprise',
        'unicode_fallback': True,
        'interactive_prompts': True,
        'progress_indicators': True,
        'error_display_format': 'detailed'
    }

# Module exports

__all__ = [
    'BannerDisplay',
    'InterfaceTerminal',
    'AliceLogger',
    'ColorCode',
    'StructuredFormatter',
    'PerformanceFilter',
    'SecurityFilter',
    'CompressedTimedRotatingFileHandler',
    'tampilkan_banner_selamat_datang',
    'setup_logger',
    'get_logger',
    'cleanup_logger',
    'display_welcome_banner',
    'create_terminal_interface',
    'create_banner_display',
    'create_logger_system',
    'get_interface_status',
    'validate_interface_environment',
    'get_interface_configuration'
]

# Interface package constants

INTERFACE_VERSION = version
DEFAULT_LOG_LEVEL = "INFO"
DEFAULT_TERMINAL_WIDTH = 80
ENTERPRISE_COLOR_SCHEME = True
UNICODE_FALLBACK_ENABLED = True

# Package initialization logging

logger = logging.getLogger(__name__)

if _interface_imports_successful:
    logger.info(f"ALICE Bot Interface Package v{version} initialized successfully")
    logger.info(f"Terminal capabilities: color={_check_color_support()}, unicode={_check_unicode_support()}")
else:
    logger.warning(f"ALICE Bot Interface Package v{version} using fallback mode: {_interface_import_error}")
    logger.info("Limited functionality available with graceful degradation")
