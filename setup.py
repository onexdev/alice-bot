"""
ALICE Bot - Advanced Legitimate Intelligence Crypto Explorer
Setup script untuk installation dan distribution dengan enterprise configuration.

Installation script yang menyediakan proper Python package installation
dengan comprehensive dependency management dan platform-specific optimizations.

Penulis: onex_dv
GitHub: https://github.com/onexdev
Lisensi: MIT Professional
Versi: 1.0.0
"""

import os
import sys
import platform
from pathlib import Path
from setuptools import setup, find_packages

# Minimum Python version requirement

PYTHON_REQUIRES = ">=3.8.0"

# Package information

PACKAGE_NAME = "alice-bot"
PACKAGE_VERSION = "1.0.0"
PACKAGE_DESCRIPTION = "Advanced Legitimate Intelligence Crypto Explorer untuk Base Network"
PACKAGE_LONG_DESCRIPTION = """
ALICE Bot adalah enterprise-grade blockchain scanner yang dirancang khusus untuk analisis
token transfer pada Base network. Sistem ini menggunakan Etherscan API v2 dengan
implementasi keamanan tingkat militer dan performa sub-detik.

Fitur Utama:
• Scanner token transfer dengan akurasi 100% untuk Base network (ChainID 8453)
• Rate limiting otomatis dengan algoritma adaptive untuk perlindungan API
• Input validation dengan tingkat keamanan forensik dan comprehensive sanitization
• Error handling komprehensif dengan recovery mechanisms dan detailed reporting
• Performance monitoring real-time dengan metrics collection dan alerting
• Encrypted credential storage menggunakan AES-256 dengan PBKDF2 key derivation
• Comprehensive logging system dengan rotation, compression, dan audit trail
• Memory management dengan automatic cleanup dan garbage collection optimization
• Cross-platform compatibility dengan OS-specific optimizations
• Enterprise-grade configuration management dengan hot reload capabilities
"""

PACKAGE_AUTHOR = "onex_dv"
PACKAGE_AUTHOR_EMAIL = "onex@example.com"
PACKAGE_URL = "https://github.com/onexdev/alice-bot"
PACKAGE_LICENSE = "MIT"

# Keywords untuk package discovery

KEYWORDS = [
    "blockchain", "ethereum", "base", "scanner", "crypto", "defi",
    "token", "transfer", "analysis", "enterprise", "security", "forensic"
]

# Classifiers untuk package categorization

CLASSIFIERS = [
    "Development Status :: 5 - Production/Stable",
    "Intended Audience :: Developers",
    "Intended Audience :: Financial and Insurance Industry",
    "Intended Audience :: Information Technology",
    "License :: OSI Approved :: MIT License",
    "Operating System :: OS Independent",
    "Operating System :: Microsoft :: Windows :: Windows 10",
    "Operating System :: POSIX :: Linux",
    "Operating System :: MacOS :: MacOS X",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.8",
    "Programming Language :: Python :: 3.9",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Topic :: Office/Business :: Financial",
    "Topic :: Security :: Cryptography",
    "Topic :: Software Development :: Libraries :: Python Modules",
    "Topic :: System :: Monitoring",
    "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
    "Environment :: Console",
    "Natural Language :: English",
    "Natural Language :: Indonesian",
    "Typing :: Typed"
]

def read_file(file_path: str) -> str:
    """Read file content dengan error handling."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        return ""
    except Exception as e:
        print(f"Warning: Error reading {file_path}: {e}")
        return ""

def get_install_requirements() -> list:
    """Load requirements dari requirements.txt dengan platform-specific filtering."""
    requirements = []
    current_platform = platform.system()

    requirements_content = read_file('requirements.txt')
    if not requirements_content:
        # Fallback requirements jika file tidak ditemukan
        return [
            "aiohttp>=3.9.0,<4.0.0",
            "aiofiles>=23.2.0,<24.0.0", 
            "cryptography>=41.0.0,<42.0.0",
            "psutil>=5.9.0,<6.0.0",
            "configparser>=5.3.0,<6.0.0",
            "pathlib2>=2.3.7,<3.0.0",
            "python-dateutil>=2.8.0,<3.0.0"
        ]

    for line in requirements_content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if ';platform_system==' in line:
            package, condition = line.split(';platform_system==')
            target_platform = condition.strip('"\'')
            if current_platform == target_platform:
                requirements.append(package.strip())
        else:
            requirements.append(line)
    return requirements

def get_extra_requirements() -> dict:
    """Define optional requirements untuk different use cases."""
    return {
        'dev': [
            'pytest>=7.4.0,<8.0.0',
            'pytest-asyncio>=0.21.0,<1.0.0',
            'coverage>=7.3.0,<8.0.0',
            'black>=23.7.0,<24.0.0',
            'flake8>=6.0.0,<7.0.0',
            'mypy>=1.5.0,<2.0.0',
            'sphinx>=7.1.0,<8.0.0',
            'sphinx-rtd-theme>=1.3.0,<2.0.0'
        ],
        'monitoring': [
            'sentry-sdk>=1.32.0,<2.0.0',
            'prometheus-client>=0.17.0,<1.0.0',
            'grafana-api>=1.0.3,<2.0.0'
        ],
        'blockchain': [
            'web3>=6.9.0,<7.0.0',
            'eth-hash>=0.5.2,<1.0.0',
            'eth-utils>=2.2.0,<3.0.0'
        ],
        'performance': [
            'uvloop>=0.17.0;platform_system!="Windows"',
            'ujson>=5.8.0,<6.0.0',
            'orjson>=3.9.0,<4.0.0',
            'cchardet>=2.1.7,<3.0.0'
        ],
        'security': [
            'keyring>=24.2.0,<25.0.0',
            'cryptography>=41.0.0,<42.0.0',
            'bcrypt>=4.0.0,<5.0.0'
        ],
        'all': []
    }

def get_entry_points() -> dict:
    """Define console entry points untuk CLI commands."""
    return {
        'console_scripts': [
            'alice=alice_bot.alice:main',
            'alice-bot=alice_bot.alice:main',
            'alice-scan=alice_bot.alice:main',
        ]
    }

def get_package_data() -> dict:
    """Define package data files yang perlu disertakan."""
    return {
        'alice_bot': [
            'config.ini',
            'locale/*.json',
            'templates/*.txt',
            'static/*'
        ]
    }

def get_data_files() -> list:
    """Define additional data files untuk installation."""
    data_files = []

    config_files = [
        ('config', ['config.ini']),
        ('docs', ['README.md', 'LICENSE']),
    ]

    examples_dir = Path('examples')
    if examples_dir.exists():
        example_files = [str(f) for f in examples_dir.glob('*') if f.is_file()]
        if example_files:
            config_files.append(('examples', example_files))

    return config_files

def validate_python_version():
    """Validate Python version compatibility."""
    if sys.version_info < (3, 8):
        print("Error: Python 3.8 atau lebih tinggi diperlukan.")
        print(f"Python version yang terdeteksi: {sys.version}")
        print("Silakan upgrade Python version sebelum instalasi.")
        sys.exit(1)

def create_directories():
    """Create necessary directories untuk package operation."""
    directories = [
        'logs',
        'result',
        'backup',
        'credentials',
        'temp'
    ]
    for directory in directories:
        Path(directory).mkdir(exist_ok=True, mode=0o755)
        gitkeep_file = Path(directory) / '.gitkeep'
        if not gitkeep_file.exists():
            gitkeep_file.touch()

def pre_install_checks():
    """Perform pre-installation checks dan setup."""
    print("ALICE Bot Installation - Pre-installation checks...")

    validate_python_version()
    print(f"✓ Python version: {sys.version.split()[0]}")

    current_platform = platform.system()
    supported_platforms = ['Windows', 'Linux', 'Darwin']

    if current_platform not in supported_platforms:
        print(f"Warning: Platform {current_platform} belum fully tested")
    else:
        print(f"✓ Platform supported: {current_platform}")

    try:
        import shutil
        free_space = shutil.disk_usage('.').free
        required_space = 100 * 1024 * 1024
        if free_space < required_space:
            print(f"Warning: Low disk space. Available: {free_space // 1024 // 1024}MB")
        else:
            print(f"✓ Disk space sufficient: {free_space // 1024 // 1024}MB available")
    except Exception as e:
        print(f"Warning: Could not check disk space: {e}")

    create_directories()
    print("✓ Required directories created")

    print("Pre-installation checks completed.\n")

def post_install_message():
    """Display post-installation instructions."""
    message = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                    ALICE Bot Installation Completed                         ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  Installation berhasil! Berikut langkah selanjutnya:                        ║
║                                                                              ║
║  1. Verifikasi instalasi:                                                    ║
║     alice --version                                                          ║
║                                                                              ║
║  2. Tampilkan bantuan:                                                       ║
║     alice h                                                                  ║
║                                                                              ║
║  3. Contoh penggunaan:                                                       ║
║     alice sc 0x1234…abcd p Vfull hasil.txt                                   ║
║                                                                              ║
║  4. File konfigurasi:                                                        ║
║     config.ini (pengaturan sistem)                                           ║
║     credentials/ (API keys terenkripsi)                                      ║
║                                                                              ║
║  5. Direktori penting:                                                       ║
║     logs/ (system logs)                                                      ║
║     result/ (output files)                                                   ║
║     backup/ (backup files)                                                   ║
║                                                                              ║
║  Dokumentasi lengkap: README.md                                              ║
║  Support: https://github.com/onexdev/alice-bot                              ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
    print(message)

# Combine all extra requirements
extras_require = get_extra_requirements()
all_extras = []
for extra_list in extras_require.values():
    if extra_list != all_extras:
        all_extras.extend(extra_list)
extras_require['all'] = list(set(all_extras))

if __name__ == "__main__":
    pre_install_checks()

    setup(
        name=PACKAGE_NAME,
        version=PACKAGE_VERSION,
        description=PACKAGE_DESCRIPTION,
        long_description=PACKAGE_LONG_DESCRIPTION,
        long_description_content_type="text/plain",
        author=PACKAGE_AUTHOR,
        author_email=PACKAGE_AUTHOR_EMAIL,
        url=PACKAGE_URL,
        packages=find_packages(),
        package_data=get_package_data(),
        data_files=get_data_files(),
        include_package_data=True,
        python_requires=PYTHON_REQUIRES,
        install_requires=get_install_requirements(),
        extras_require=extras_require,
        entry_points=get_entry_points(),
        license=PACKAGE_LICENSE,
        keywords=" ".join(KEYWORDS),
        classifiers=CLASSIFIERS,
        platforms=["Windows", "Linux", "macOS"],
        zip_safe=False,
        project_urls={
            "Homepage": PACKAGE_URL,
            "Documentation": f"{PACKAGE_URL}/wiki",
            "Repository": PACKAGE_URL,
            "Bug Tracker": f"{PACKAGE_URL}/issues",
            "Changelog": f"{PACKAGE_URL}/releases",
            "Funding": f"{PACKAGE_URL}/sponsors"
        }
    )

    post_install_message()
