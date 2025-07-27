"""
Interface Terminal Module untuk ALICE Bot - Professional Colored Terminal Interface
Modul untuk menangani output terminal dengan color support dan formatting enterprise.

Modul ini menangani:

- Colored output dengan ANSI escape codes
- Terminal compatibility detection
- Professional step-by-step debugging display
- User confirmation dengan validation
- Error messaging dengan severity levels
- Progress indication dan status updates
- Cross-platform terminal support
- Safe fallback untuk environment tanpa color

Penulis: onex_dv
GitHub: https://github.com/onexdev
Lisensi: MIT Professional
Versi: 1.0.0
"""

import sys
import os
import platform
import time
from typing import Optional, Any
from enum import Enum
import logging

class ColorCode(Enum):
    """Enum untuk ANSI color codes dengan enterprise color scheme."""
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'

    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'

    BRIGHT_BLACK = '\033[90m'
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'

    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'

class InterfaceTerminal:
    """
    Interface terminal enterprise dengan color support dan professional formatting.
    Menangani semua output ke terminal dengan compatibility dan error handling.
    """

    def __init__(self, logger: Optional[logging.Logger] = None, enable_colors: Optional[bool] = None):
        """
        Inisialisasi interface terminal dengan deteksi capabilities.

        Args:
            logger: Optional logger instance untuk audit
            enable_colors: Force enable/disable colors (None untuk auto-detect)
        """
        self.logger = logger or logging.getLogger(__name__)
        if enable_colors is None:
            self.color_enabled = self._detect_color_support()
        else:
            self.color_enabled = enable_colors
        self.terminal_width = self._get_terminal_width()
        self.supports_unicode = self._detect_unicode_support()
        self.colors = {
            'success': ColorCode.BRIGHT_GREEN,
            'error': ColorCode.BRIGHT_RED,
            'warning': ColorCode.YELLOW,
            'info': ColorCode.BLUE,
            'step': ColorCode.CYAN,
            'highlight': ColorCode.MAGENTA,
            'normal': ColorCode.WHITE,
            'dim': ColorCode.DIM,
            'bold': ColorCode.BOLD
        }
        self.logger.debug(f"Terminal interface initialized: colors={self.color_enabled}, width={self.terminal_width}")

    def _detect_color_support(self) -> bool:
        """Deteksi apakah terminal mendukung ANSI colors."""
        try:
            if os.environ.get('NO_COLOR'):
                return False
            if os.environ.get('FORCE_COLOR'):
                return True
            term = os.environ.get('TERM', '').lower()
            if term in ['dumb', 'unknown', '']:
                return False
            if not hasattr(sys.stdout, 'isatty') or not sys.stdout.isatty():
                return False
            if platform.system() == 'Windows':
                try:
                    import subprocess
                    subprocess.run([''], shell=True, check=False)
                    return True
                except:
                    return False
            return True
        except Exception as e:
            self.logger.debug(f"Color detection error: {e}")
            return False

    def _get_terminal_width(self) -> int:
        """Dapatkan lebar terminal untuk formatting."""
        try:
            import shutil
            return shutil.get_terminal_size().columns
        except:
            try:
                return int(os.environ.get('COLUMNS', 80))
            except:
                return 80

    def _detect_unicode_support(self) -> bool:
        """Deteksi apakah terminal mendukung Unicode."""
        try:
            if sys.stdout.encoding and 'utf' in sys.stdout.encoding.lower():
                return True
            return False
        except:
            return False

    def _format_with_color(self, text: str, color: ColorCode, bold: bool = False) -> str:
        """Format text dengan color dan reset."""
        if not self.color_enabled:
            return text
        code = color.value
        if bold:
            code = ColorCode.BOLD.value + code
        return f"{code}{text}{ColorCode.RESET.value}"

    def _print_colored(self, text: str, color: ColorCode, bold: bool = False, prefix: str = "", suffix: str = ""):
        """Print text dengan color formatting."""
        formatted = self._format_with_color(text, color, bold)
        print(f"{prefix}{formatted}{suffix}")

    def print_success(self, message: str, bold: bool = True):
        """Print success message dengan green color."""
        self._print_colored(message, self.colors['success'], bold)
        self.logger.info(f"SUCCESS: {message}")

    def print_error(self, message: str, bold: bool = True):
        """Print error message dengan bright red color."""
        self._print_colored(message, self.colors['error'], bold)
        self.logger.error(f"ERROR: {message}")

    def print_warning(self, message: str, bold: bool = False):
        """Print warning message dengan yellow color."""
        self._print_colored(message, self.colors['warning'], bold)
        self.logger.warning(f"WARNING: {message}")

    def print_info(self, message: str, bold: bool = False):
        """Print info message dengan blue color."""
        self._print_colored(message, self.colors['info'], bold)
        self.logger.info(f"INFO: {message}")

    def print_step(self, message: str, bold: bool = False):
        """Print step message dengan cyan color untuk debugging."""
        timestamp = time.strftime("%H:%M:%S")
        text = f"[{timestamp}] {message}"
        self._print_colored(text, self.colors['step'], bold)
        self.logger.debug(f"STEP: {message}")

    def print_highlight(self, message: str, bold: bool = True):
        """Print highlighted message dengan magenta color."""
        self._print_colored(message, self.colors['highlight'], bold)
        self.logger.info(f"HIGHLIGHT: {message}")

    def print_normal(self, message: str):
        """Print normal message tanpa color khusus."""
        print(message)
        self.logger.debug(f"NORMAL: {message}")

    def print_separator(self, char: str = "=", length: Optional[int] = None):
        """Print separator line dengan panjang yang ditentukan."""
        if length is None:
            length = min(self.terminal_width, 80)
        sep = char * length
        self._print_colored(sep, self.colors['dim'])

    def print_header(self, title: str, char: str = "="):
        """Print header dengan title di tengah."""
        if len(title) + 4 >= self.terminal_width:
            self._print_colored(title, self.colors['bold'], True)
            return
        pad = self.terminal_width - len(title) - 2
        left = pad // 2
        right = pad - left
        header = f"{char*left} {title} {char*right}"
        self._print_colored(header, self.colors['highlight'], True)

    def konfirmasi_scan_detail(self) -> bool:
        """
        Konfirmasi user untuk memulai scanning dengan detail validation.

        Returns:
            bool: True jika user konfirmasi, False jika membatalkan
        """
        try:
            while True:
                self.print_separator("-")
                prompt = self._format_with_color(
                    "Apakah Anda ingin memulai scanning sekarang? (y/n): ",
                    self.colors['highlight'], bold=True
                )
                resp = input(prompt).strip().lower()
                if resp in ['y', 'yes', 'ya', '1']:
                    self.print_success("Konfirmasi diterima, memulai scanning...")
                    return True
                if resp in ['n', 'no', 'tidak', '0']:
                    self.print_warning("Scanning dibatalkan oleh pengguna")
                    return False
                self.print_error("Input tidak valid. Gunakan 'y' untuk ya atau 'n' untuk tidak.")
        except KeyboardInterrupt:
            self.print_warning("\nOperasi dibatalkan oleh pengguna (Ctrl+C)")
            return False
        except Exception as e:
            self.logger.error(f"Error dalam konfirmasi user: {e}")
            self.print_error("Error dalam proses konfirmasi")
            return False

    def konfirmasi_scan(self, wallet: str, versi: str, output_file: str) -> bool:
        """
        Konfirmasi scanning dengan parameter yang ditampilkan.

        Args:
            wallet: Alamat wallet target
            versi: Versi output format
            output_file: Nama file output

        Returns:
            bool: True jika dikonfirmasi
        """
        self.print_separator("=")
        self.print_header("KONFIRMASI OPERASI SCANNING")
        self.print_info(f"Target Wallet    : {wallet}")
        self.print_info(f"Format Output    : {versi}")
        self.print_info(f"File Output      : result/{output_file}")
        self.print_info("API Endpoint     : Etherscan API v2 (Base Network)")
        return self.konfirmasi_scan_detail()

    def tampilkan_progress(self, current: int, total: int, operation: str = "Processing"):
        """
        Tampilkan progress bar sederhana.

        Args:
            current: Progress saat ini
            total: Total items
            operation: Nama operasi yang sedang berjalan
        """
        percentage = 100 if total == 0 else min(100, (current * 100) // total)
        bar_len = 30
        filled = (percentage * bar_len) // 100
        bar = "█" * filled + "░" * (bar_len - filled)
        text = f"{operation}: [{bar}] {percentage}% ({current}/{total})"
        if self.color_enabled:
            bar_colored = self._format_with_color(bar, self.colors['info'])
            text = f"{operation}: [{bar_colored}] {percentage}% ({current}/{total})"
        print(f"\r{text}", end="", flush=True)
        if current >= total:
            print()

    def print_table_header(self, headers: list, column_widths: list):
        """Print table header dengan formatting."""
        if len(headers) != len(column_widths):
            raise ValueError("Headers dan column_widths harus sama panjangnya")
        sep = "+" + "+".join("-" * (w + 2) for w in column_widths) + "+"
        self._print_colored(sep, self.colors['dim'])
        row = "|"
        for h, w in zip(headers, column_widths):
            row += f" {h:<{w}} |"
        self._print_colored(row, self.colors['bold'], True)
        self._print_colored(sep, self.colors['dim'])

    def print_table_row(self, values: list, column_widths: list, highlight: bool = False):
        """Print table row dengan formatting."""
        if len(values) != len(column_widths):
            raise ValueError("Values dan column_widths harus sama panjangnya")
        row = "|"
        for v, w in zip(values, column_widths):
            s = str(v)
            if len(s) > w:
                s = s[:w-3] + "..."
            row += f" {s:<{w}} |"
        col = self.colors['highlight'] if highlight else self.colors['normal']
        self._print_colored(row, col)

    def print_table_footer(self, column_widths: list):
        """Print table footer separator."""
        sep = "+" + "+".join("-" * (w + 2) for w in column_widths) + "+"
        self._print_colored(sep, self.colors['dim'])

    def tampilkan_bantuan_lengkap(self):
        """Tampilkan bantuan penggunaan yang lengkap."""
        help_text = """
ALICE BOT - Advanced Legitimate Intelligence Crypto Explorer
Enterprise Blockchain Scanner untuk Base Network

PENGGUNAAN:
python alice.py <perintah> <parameter…>

PERINTAH TERSEDIA:
sc <wallet> p <versi> [file]  - Scan token transfers
h                             - Tampilkan bantuan ini

PARAMETER:
<wallet>    - Alamat wallet Base network (format: 0x + 40 hex chars)
p           - Perintah print untuk aktivasi output
<versi>     - Format output:
              Vfull : Format lengkap (hash|method|age|from|to|token)
              Vfrom : Hanya alamat pengirim
[file]      - Nama file output (opsional, auto-generate jika kosong)

INFORMASI API:
- Menggunakan Etherscan API v2 untuk Base Network (ChainID: 8453)
- Endpoint: https://api.etherscan.io/v2/api?chainid=8453
- Rate limiting: 5 requests per detik (otomatis)
- Timeout: 30 detik per request
- Retry mechanism: 3 kali dengan exponential backoff

FITUR KEAMANAN:
- Input validation dengan regex forensik
- API key encryption dengan AES-256
- Rate limiting otomatis untuk perlindungan API
- Comprehensive error handling dan recovery
- Atomic file operations untuk konsistensi data
- Memory management dengan batas 50MB

PERFORMA:
- Target eksekusi: Sub-detik (< 1 detik)
- Connection pooling untuk optimasi network
- Response caching untuk mengurangi API calls
- Batch processing untuk dataset besar

KEAMANAN:
- Hanya mengakses data publik blockchain
- Tidak menyimpan private key atau data sensitif
- Audit logging untuk semua operasi
- Secure credential storage

SUPPORT:
- Penulis: onex_dv
- GitHub: https://github.com/onexdev
- Lisensi: MIT Professional
"""
        self.print_separator("=")
        self.print_header("BANTUAN ALICE BOT")
        print(help_text)
        self.print_separator("=")

    def print_debug_info(self, info: dict):
        """Print debug information dengan formatting."""
        self.print_separator("-")
        self.print_highlight("DEBUG INFORMATION:")
        for k, v in info.items():
            key_fmt = f"{k}:".ljust(20)
            self.print_info(f"  {key_fmt} {v}")
        self.print_separator("-")

    def print_error_details(self, error: Exception, context: dict = None):
        """Print error details dengan context information."""
        self.print_separator("=")
        self.print_error(f"ERROR: {type(error).__name__}")
        self.print_error(f"Message: {error}")
        if context:
            self.print_warning("Context Information:")
            for k, v in context.items():
                self.print_info(f"  {k}: {v}")
        self.print_separator("=")

    def cleanup(self):
        """Cleanup terminal state."""
        if self.color_enabled:
            print(ColorCode.RESET.value, end="")
        self.logger.debug("Terminal interface cleaned up")

if __name__ == "__main__":
    terminal = InterfaceTerminal()
    terminal.print_success("Test success message")
    terminal.print_error("Test error message")
    terminal.print_warning("Test warning message")
    terminal.print_info("Test info message")
    terminal.print_step("Test step message")
    terminal.print_highlight("Test highlight message")

    for i in range(11):
        terminal.tampilkan_progress(i, 10, "Testing")
        time.sleep(0.1)

    terminal.cleanup()
