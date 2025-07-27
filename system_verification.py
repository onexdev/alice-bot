#!/usr/bin/env python3
"""
ALICE Bot System Verification Script - Comprehensive Testing Framework
Script verifikasi komprehensif untuk memastikan semua komponen sistem berfungsi dengan sempurna.

Script ini melakukan testing menyeluruh terhadap semua modul, dependencies, dan integrasi
untuk memastikan sistem siap dijalankan tanpa error dalam environment production.

Penulis: onex_dv
GitHub: https://github.com/onexdev
Lisensi: MIT Professional
Versi: 1.0.0
"""

import sys
import os
import asyncio
import traceback
import time
from pathlib import Path
from typing import Dict, Any, List, Tuple

# ===== Add project root to path =====
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

class SystemVerificationFramework:
    """
    Framework verifikasi sistem enterprise dengan comprehensive testing capabilities.
    Melakukan testing terhadap semua aspek sistem untuk memastikan kesiapan production.
    """

    def __init__(self):
        """Inisialisasi framework verifikasi dengan comprehensive test suite."""
        self.test_results = {
            'total_tests': 0,
            'passed_tests': 0,
            'failed_tests': 0,
            'warnings': 0,
            'errors': [],
            'warnings_list': [],
            'test_details': {}
        }
        self.verification_start_time = time.time()

    def log_test_result(self, test_name: str, passed: bool, details: str = "", warning: bool = False):
        """Log hasil test dengan detailed information."""
        self.test_results['total_tests'] += 1

        if passed:
            self.test_results['passed_tests'] += 1
            status = "PASS"
            if warning:
                self.test_results['warnings'] += 1
                self.test_results['warnings_list'].append(f"{test_name}: {details}")
                status = "PASS (WARNING)"
        else:
            self.test_results['failed_tests'] += 1
            self.test_results['errors'].append(f"{test_name}: {details}")
            status = "FAIL"

        self.test_results['test_details'][test_name] = {
            'status': status,
            'details': details,
            'timestamp': time.time()
        }

        print(f"[{status}] {test_name}")
        if details:
            print(f"         {details}")

    def test_python_environment(self):
        """Test Python environment dan version compatibility."""
        print("\n=== TESTING PYTHON ENVIRONMENT ===")

        python_version = sys.version_info
        required_version = (3, 8)

        if python_version >= required_version:
            self.log_test_result(
                "Python Version",
                True,
                f"Python {python_version.major}.{python_version.minor}.{python_version.micro} (required: {required_version[0]}.{required_version[1]}+)"
            )
        else:
            self.log_test_result(
                "Python Version",
                False,
                f"Python {python_version.major}.{python_version.minor} insufficient, requires {required_version[0]}.{required_version[1]}+"
            )

        import platform
        system = platform.system()
        supported_platforms = ['Windows', 'Linux', 'Darwin']

        if system in supported_platforms:
            self.log_test_result("Platform Compatibility", True, f"Platform {system} supported")
        else:
            self.log_test_result("Platform Compatibility", True, f"Platform {system} not fully tested", warning=True)

    def test_directory_structure(self):
        """Test struktur direktori dan file permissions."""
        print("\n=== TESTING DIRECTORY STRUCTURE ===")

        required_directories = [
            'core', 'interface', 'security', 'logs', 'result',
            'backup', 'credentials', 'temp'
        ]

        all_dirs_exist = True
        for directory in required_directories:
            dir_path = Path(directory)

            if dir_path.exists():
                try:
                    test_file = dir_path / '.write_test'
                    test_file.touch()
                    test_file.unlink()
                    self.log_test_result(f"Directory {directory}", True, "Exists with write permission")
                except Exception as e:
                    self.log_test_result(f"Directory {directory}", False, f"No write permission: {str(e)}")
                    all_dirs_exist = False
            else:
                try:
                    dir_path.mkdir(exist_ok=True, mode=0o755)
                    self.log_test_result(f"Directory {directory}", True, "Created successfully")
                except Exception as e:
                    self.log_test_result(f"Directory {directory}", False, f"Cannot create: {str(e)}")
                    all_dirs_exist = False

        return all_dirs_exist

    def test_core_module_imports(self):
        """Test import semua core modules."""
        print("\n=== TESTING CORE MODULE IMPORTS ===")

        import_tests = [
            ('alice_bot', 'Main package'),
            ('alice_bot.core', 'Core package'),
            ('alice_bot.core.scanner', 'Scanner module'),
            ('alice_bot.core.config', 'Config module'),
            ('alice_bot.core.validator', 'Validator module'),
            ('alice_bot.core.utils', 'Utils module'),
            ('alice_bot.core.exceptions', 'Exceptions module'),
            ('alice_bot.interface', 'Interface package'),
            ('alice_bot.interface.banner', 'Banner module'),
            ('alice_bot.interface.terminal', 'Terminal module'),
            ('alice_bot.interface.logger', 'Logger module'),
            ('alice_bot.security', 'Security package'),
            ('alice_bot.security.rate_limiter', 'Rate limiter module')
        ]

        all_imports_successful = True

        for module_name, description in import_tests:
            try:
                __import__(module_name)
                self.log_test_result(f"Import {description}", True, f"Module {module_name} imported successfully")
            except ImportError as e:
                self.log_test_result(f"Import {description}", False, f"ImportError: {str(e)}")
                all_imports_successful = False
            except Exception as e:
                self.log_test_result(f"Import {description}", False, f"Unexpected error: {str(e)}")
                all_imports_successful = False

        return all_imports_successful

    def test_dependencies(self):
        """Test availability dan compatibility dari dependencies."""
        print("\n=== TESTING DEPENDENCIES ===")

        required_dependencies = [
            ('aiohttp', 'Async HTTP client'),
            ('aiofiles', 'Async file operations'),
            ('cryptography', 'Encryption support'),
            ('psutil', 'System monitoring'),
            ('configparser', 'Configuration parsing')
        ]

        optional_dependencies = [
            ('uvloop', 'Performance enhancement'),
            ('ujson', 'Fast JSON parsing'),
            ('loguru', 'Advanced logging')
        ]

        all_required_available = True

        for dep_name, description in required_dependencies:
            try:
                __import__(dep_name)
                self.log_test_result(f"Required Dependency {dep_name}", True, description)
            except ImportError:
                self.log_test_result(f"Required Dependency {dep_name}", False, f"Missing required dependency: {dep_name}")
                all_required_available = False

        for dep_name, description in optional_dependencies:
            try:
                __import__(dep_name)
                self.log_test_result(f"Optional Dependency {dep_name}", True, description)
            except ImportError:
                self.log_test_result(f"Optional Dependency {dep_name}", True, f"Optional dependency not available: {dep_name}", warning=True)

        return all_required_available

    # ==== FUNGSI SELANJUTNYA DISAMBUNG SESUAI STRUKTUR KODE ANDA ====

# ===== ENTRY POINT =====
async def main():
    """Main verification function."""
    print("ALICE Bot System Verification Framework")
    print("Comprehensive testing untuk memastikan kesiapan production")
    print("=" * 80)

    framework = SystemVerificationFramework()
    framework.test_python_environment()
    framework.test_directory_structure()
    framework.test_core_module_imports()
    framework.test_dependencies()
    framework.test_core_functionality()
    framework.test_configuration_system()
    framework.test_api_configuration()
    framework.test_system_resources()
    await framework.test_async_functionality()
    framework.test_command_line_interface()
    success = framework.generate_verification_report()

    if success:
        print("\nSistem ALICE Bot siap untuk digunakan!")
        print("Jalankan: python alice.py h untuk bantuan")
        return 0
    else:
        print("\nSistem memerlukan perbaikan sebelum dapat digunakan.")
        return 1

if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\nVerifikasi dihentikan oleh user")
        sys.exit(130)
    except Exception as e:
        print(f"\nError dalam verifikasi: {str(e)}")
        traceback.print_exc()
        sys.exit(1)
