"""
Interface Banner Module untuk ALICE Bot - Professional Welcome Display
Modul untuk menampilkan banner selamat datang dengan desain enterprise dan informasi sistem.

Modul ini menangani:

- Display banner profesional dengan ASCII art
- Informasi sistem dan versi
- Status koneksi dan konfigurasi
- Branding dan credit information
- Terminal compatibility check
- Color support detection

Penulis: onex_dv
GitHub: https://github.com/onexdev
Lisensi: MIT Professional
Versi: 1.0.0
"""

import os
import sys
import platform
from datetime import datetime
from typing import Optional
import logging

class BannerDisplay:
    """
    Class untuk menampilkan banner selamat datang dengan design enterprise.
    Menangani deteksi terminal capabilities dan rendering yang compatible.
    """

    # ASCII Art Banner untuk ALICE
    ALICE_BANNER = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║    █████╗ ██╗     ██╗ ██████╗███████╗    ██████╗  ██████╗ ████████╗         ║
║   ██╔══██╗██║     ██║██╔════╝██╔════╝    ██╔══██╗██╔═══██╗╚══██╔══╝         ║
║   ███████║██║     ██║██║     █████╗      ██████╔╝██║   ██║   ██║            ║
║   ██╔══██║██║     ██║██║     ██╔══╝      ██╔══██╗██║   ██║   ██║            ║
║   ██║  ██║███████╗██║╚██████╗███████╗    ██████╔╝╚██████╔╝   ██║            ║
║   ╚═╝  ╚═╝╚══════╝╚═╝ ╚═════╝╚══════╝    ╚═════╝  ╚═════╝    ╚═╝            ║
║                                                                              ║
║              Advanced Legitimate Intelligence Crypto Explorer                ║
║                     Enterprise Blockchain Scanner v1.0.0                    ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

    # Informasi sistem dan konfigurasi
    SYSTEM_INFO_TEMPLATE = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                              INFORMASI SISTEM                               ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Penulis           : onex_dv                                                 ║
║  GitHub            : https://github.com/onexdev                              ║
║  Lisensi           : MIT Professional                                        ║
║  Tingkat Keamanan  : Enterprise Grade                                        ║
║  Versi Python      : {python_version:<50} ║
║  Platform          : {platform:<50} ║
║  Waktu Sistem      : {current_time:<50} ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                            KONFIGURASI ENTERPRISE                            ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  API Target        : Etherscan API v2 (Base Network - ChainID 8453)         ║
║  Endpoint          : https://api.etherscan.io/v2/api?chainid=8453            ║
║  Rate Limiting     : 5 requests per detik (otomatis)                        ║
║  Error Handling    : Comprehensive dengan retry mechanism                   ║
║  Performa Target   : Sub-detik execution (< 1 second)                       ║
║  Memory Limit      : 50MB maksimal untuk operasi normal                     ║
║  Security Level    : Production-grade dengan input validation               ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                              DOKUMENTASI KRITIS                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  • Bot ini menggunakan Etherscan API v2 dengan Base Network ChainID 8453     ║
║  • Rate limiting otomatis untuk melindungi dari API abuse                    ║
║  • Error handling komprehensif untuk semua skenario kegagalan                ║
║  • Performa eksekusi dijamin di bawah 1 detik untuk operasi normal           ║
║  • Input validation dengan tingkat keamanan forensik                         ║
║  • Atomic file operations untuk konsistensi data                             ║
║  • Comprehensive logging dengan audit trail                                  ║
║  • Memory management dengan garbage collection otomatis                      ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Inisialisasi banner display dengan deteksi terminal capabilities.

        Args:
            logger: Optional logger instance untuk debugging
        """
        self.logger = logger or logging.getLogger(__name__)
        self.terminal_width = self._detect_terminal_width()
        self.supports_unicode = self._detect_unicode_support()
        self.supports_color = self._detect_color_support()

    def _detect_terminal_width(self) -> int:
        """Deteksi lebar terminal untuk responsive display."""
        try:
            import shutil
            terminal_size = shutil.get_terminal_size()
            return terminal_size.columns
        except:
            try:
                return int(os.environ.get('COLUMNS', 80))
            except:
                return 80

    def _detect_unicode_support(self) -> bool:
        """Deteksi apakah terminal mendukung Unicode characters."""
        try:
            if sys.stdout.encoding and 'utf' in sys.stdout.encoding.lower():
                return True
            if platform.system() == 'Windows':
                return False
            return True
        except:
            return False

    def _detect_color_support(self) -> bool:
        """Deteksi apakah terminal mendukung ANSI color codes."""
        try:
            term = os.environ.get('TERM', '').lower()
            if term in ['dumb', 'unknown']:
                return False
            if any(env in os.environ for env in ['PYCHARM_HOSTED', 'CI', 'GITHUB_ACTIONS']):
                return False
            if platform.system() == 'Windows':
                try:
                    version = platform.version()
                    if '10.' in version:
                        return True
                except:
                    pass
                return False
            return True
        except:
            return False

    def _get_system_info(self) -> dict:
        """Kumpulkan informasi sistem untuk display."""
        try:
            return {
                'python_version': f"{platform.python_version()} ({platform.python_implementation()})",
                'platform': f"{platform.system()} {platform.release()} {platform.machine()}",
                'current_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S WIB"),
                'terminal_width': self.terminal_width,
                'unicode_support': self.supports_unicode,
                'color_support': self.supports_color
            }
        except Exception as e:
            self.logger.warning(f"Error getting system info: {e}")
            return {
                'python_version': "Unknown",
                'platform': "Unknown",
                'current_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'terminal_width': 80,
                'unicode_support': False,
                'color_support': False
            }

    def _print_safe(self, text: str, fallback_text: Optional[str] = None):
        """Print text dengan fallback untuk compatibility."""
        try:
            if self.supports_unicode:
                print(text)
            else:
                if fallback_text:
                    print(fallback_text)
                else:
                    ascii_text = (text
                                  .replace('╔', '+').replace('╗', '+')
                                  .replace('╚', '+').replace('╝', '+')
                                  .replace('║', '|').replace('═', '=')
                                  .replace('╠', '+').replace('╣', '+')
                                  .replace('╦', '+').replace('╩', '+')
                                  .replace('╬', '+'))
                    print(ascii_text)
        except Exception as e:
            self.logger.warning(f"Error printing text: {e}")
            print("=" * 80)

    def tampilkan_banner_utama(self):
        """Tampilkan banner utama ALICE dengan ASCII art."""
        try:
            os.system('cls' if platform.system() == 'Windows' else 'clear')
            if self.supports_unicode:
                self._print_safe(self.ALICE_BANNER)
            else:
                fallback_banner = """
+==============================================================================+
|                                                                              |
|     ALICE BOT - Advanced Legitimate Intelligence Crypto Explorer            |
|                     Enterprise Blockchain Scanner v1.0.0                     |
|                                                                              |
+==============================================================================+
"""
                self._print_safe(fallback_banner)
            print()
        except Exception as e:
            self.logger.error(f"Error displaying main banner: {e}")
            print("=" * 80)
            print("ALICE BOT - Enterprise Blockchain Scanner v1.0.0")
