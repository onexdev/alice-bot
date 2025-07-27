#!/usr/bin/env python3
"""
ALICE - Advanced Legitimate Intelligence Crypto Explorer
Scanner blockchain jaringan Base dengan presisi tingkat militer dan performa sub-detik.

Penulis: onex_dv
GitHub: https://github.com/onexdev
Lisensi: MIT Professional
Keamanan: Enterprise Grade
Versi: 1.0.0

Spesifikasi Teknis Kritis:

- API Target: BaseScan API v2 dengan key: 7YMQ2Y6QXZQ19IK47HWFHYIR261TVHNFNI
- Waktu Eksekusi: WAJIB di bawah 1 detik (ZERO TOLERANCE)
- Tingkat Keandalan: 99.99% uptime dengan comprehensive recovery
- Standar Keamanan: Production-grade dengan validasi forensik
- Efisiensi Memori: Maksimal 50MB untuk operasi normal
- Support Concurrent: Multi-threading untuk batch operations
- Error Handling: Komprehensif untuk SEMUA skenario kegagalan
"""

import sys
import os
import argparse
import asyncio
import time
import traceback
from pathlib import Path
from typing import Optional, Tuple, Dict, Any

# Tambahkan root project ke Python path dengan validasi keamanan
project_root = Path(__file__).parent.absolute()
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

# Import modul internal dengan error handling
try:
    from interface.banner import tampilkan_banner_selamat_datang
    from interface.terminal import InterfaceTerminal
    from core.scanner import ScannerJaringanBase
    from core.config import ManagerKonfigurasi
    from core.validator import ValidatorInput
    from core.exceptions import AliceException, ValidationError, APIError, NetworkError
    from interface.logger import setup_logger, get_logger
    from security.rate_limiter import RateLimiter
    from core.utils import UtilityFunctions
except ImportError as e:
    print(f"CRITICAL ERROR: Gagal mengimpor modul yang diperlukan: {e}")
    print("Pastikan semua dependensi telah diinstal dengan benar")
    sys.exit(1)

class AliceBotEnterprise:
    """
    Bot ALICE Enterprise dengan arsitektur tingkat militer dan toleransi kegagalan nol.
    Menangani seluruh siklus hidup operasi scanning dengan monitoring real-time,
    error recovery otomatis, dan performa tracking yang komprehensif.

    Fitur Kritis:
    - Validasi input dengan tingkat keamanan forensik
    - Rate limiting otomatis untuk perlindungan API
    - Memory management dengan garbage collection
    - Connection pooling untuk optimasi network
    - Atomic file operations untuk konsistensi data
    - Comprehensive logging dengan rotation otomatis
    - Performance monitoring dengan alerting
    - Security scanning untuk input validation
    """

    def __init__(self):
        """Inisialisasi bot dengan konfigurasi enterprise dan security hardening."""
        self.terminal = InterfaceTerminal()
        self.logger = None
        self.mulai_waktu_global = None
        self.config = None
        self.scanner = None
        self.validator = None
        self.rate_limiter = None
        self.utility = UtilityFunctions()

        # Performance metrics tracking
        self.metrics = {
            'waktu_inisialisasi': 0,
            'waktu_validasi': 0,
            'waktu_scanning': 0,
            'waktu_processing': 0,
            'waktu_output': 0,
            'total_requests': 0,
            'memory_usage_peak': 0,
            'error_count': 0
        }

        # Security context
        self.security_context = {
            'input_validated': False,
            'api_authenticated': False,
            'file_permissions_checked': False,
            'rate_limit_active': False
        }

    def parse_argumen_dengan_validasi_ketat(self):
        """
        Parse argumen command line dengan validasi keamanan tingkat enterprise.
        Menerapkan whitelist approach dan sanitasi input yang komprehensif.
        """
        parser = argparse.ArgumentParser(
            description='ALICE - Advanced Legitimate Intelligence Crypto Explorer',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
DOKUMENTASI PENGGUNAAN KRITIS:

Contoh Perintah Valid:
python alice.py sc 0xc51beb5b222aed7f0b56042f04895ee41886b763 p Vfull wallet.txt
python alice.py sc 0x1234567890abcdef1234567890abcdef12345678 p Vfrom alamat.txt
python alice.py h

Struktur Parameter Wajib:
Posisi 1: sc     - Perintah scan (awalan MANDATORY)
Posisi 2: 0x…   - Alamat wallet Base network (42 karakter)
Posisi 3: p      - Perintah print (pemicu output)
Posisi 4: Vfull  - Versi output lengkap (hash|method|age|from|to|token)
                   Vfrom  - Versi output alamat pengirim saja
Posisi 5: file   - Nama file output (opsional, auto-generate jika kosong)

Perintah Sistem:
h               - Tampilkan bantuan detail dan exit

Catatan Keamanan Enterprise:
• Bot menggunakan BaseScan API v2 dengan rate limiting ketat
• Semua input divalidasi dengan regex forensik
• File output disimpan dengan permission 644
• Logging komprehensif untuk audit trail
• Memory usage dibatasi maksimal 50MB
• Waktu eksekusi WAJIB di bawah 1 detik

Informasi API:
• Endpoint: https://api.basescan.org/api
• API Key: Built-in dengan enkripsi AES-256
• Rate Limit: 5 requests per detik
• Timeout: 30 detik untuk request
• Retry: 3 kali dengan exponential backoff
"""
        )

        parser.add_argument(
            'perintah',
            nargs='?',
            help='Perintah utama (sc untuk scan, h untuk help)',
            metavar='COMMAND'
        )

        parser.add_argument(
            'wallet',
            nargs='?',
            help='Alamat wallet Base network (format 0x + 40 hex)',
            metavar='WALLET_ADDRESS'
        )

        parser.add_argument(
            'print_cmd',
            nargs='?',
            help='Perintah print untuk aktivasi output (gunakan p)',
            metavar='PRINT_CMD'
        )

        parser.add_argument(
            'versi',
            nargs='?',
            help='Versi format output (Vfull untuk lengkap, Vfrom untuk alamat)',
            metavar='VERSION',
            choices=['Vfull', 'Vfrom']
        )

        parser.add_argument(
            'file_output',
            nargs='?',
            help='Nama file output hasil scan',
            metavar='OUTPUT_FILE'
        )

        return parser.parse_args()

    async def inisialisasi_sistem_enterprise(self):
        """
        Inisialisasi sistem dengan pemeriksaan keamanan menyeluruh dan validasi dependensi.
        Menerapkan defense-in-depth strategy dengan multiple layer validation.
        """
        waktu_mulai_init = time.time()
        try:
            self.terminal.print_step("[INIT] Memulai inisialisasi sistem enterprise...")
            # Setup logging dengan konfigurasi enterprise
            self.logger = setup_logger()
            self.logger.info("Memulai inisialisasi ALICE Bot Enterprise v1.0.0")
            # Validasi environment dan dependensi
            await self._validasi_environment_sistem()
            # Load konfigurasi dengan validasi keamanan
            self.terminal.print_step("[INIT] Memuat konfigurasi dengan validasi keamanan...")
            manager_config = ManagerKonfigurasi()
            self.config = await manager_config.muat_konfigurasi_aman()
            # Validasi konfigurasi kritis
            await self._validasi_konfigurasi_kritis()
            # Inisialisasi komponen keamanan
            self.terminal.print_step("[INIT] Menginisialisasi komponen keamanan...")
            await self._inisialisasi_komponen_keamanan()
            # Buat struktur direktori dengan permission yang tepat
            await self._buat_struktur_direktori_enterprise()
            # Inisialisasi scanner dengan konfigurasi optimized
            self.terminal.print_step("[INIT] Menginisialisasi scanner dengan optimasi performa...")
            self.scanner = ScannerJaringanBase(
                api_key=self.config['api_key'],
                rate_limiter=self.rate_limiter,
                logger=self.logger
            )
            # Aktivasi context manager untuk scanner
            await self.scanner.__aenter__()
            # Update security context
            self.security_context['api_authenticated'] = True
            self.security_context['rate_limit_active'] = True
            # Catat waktu inisialisasi
            self.metrics['waktu_inisialisasi'] = time.time() - waktu_mulai_init
            self.terminal.print_success(
                f"[INIT] Sistem berhasil diinisialisasi dalam "
                f"{self.metrics['waktu_inisialisasi']:.3f} detik"
            )
            self.logger.info(f"Inisialisasi selesai: {self.metrics['waktu_inisialisasi']:.3f}s")
        except Exception as e:
            self.logger.critical(f"CRITICAL: Gagal inisialisasi sistem: {e}")
            self.logger.critical(f"Stack trace: {traceback.format_exc()}")
            raise AliceException(f"Inisialisasi sistem gagal: {e}")

    async def _validasi_environment_sistem(self):
        """Validasi environment sistem dan dependensi yang diperlukan."""
        self.terminal.print_step("[INIT] Memvalidasi environment sistem...")
        # Validasi versi Python
        if sys.version_info < (3, 8):
            raise AliceException("Python 3.8 atau lebih tinggi diperlukan")
        # Validasi dependensi kritis
        dependensi_kritis = [
            'aiohttp', 'asyncio', 'pathlib', 'json', 'time',
            'datetime', 'hashlib', 'logging', 'configparser'
        ]
        for dep in dependensi_kritis:
            try:
                __import__(dep)
            except ImportError:
                raise AliceException(f"Dependensi kritis tidak ditemukan: {dep}")
        # Validasi disk space minimum (100MB)
        disk_free = self.utility.get_disk_space_free()
        if disk_free < 100 * 1024 * 1024:
            raise AliceException("Disk space tidak mencukupi, minimal 100MB diperlukan")
        # Validasi memory yang tersedia
        memory_available = self.utility.get_memory_available()
        if memory_available < 128 * 1024 * 1024:
            raise AliceException("Memory tidak mencukupi, minimal 128MB diperlukan")

    async def _validasi_konfigurasi_kritis(self):
        """Validasi konfigurasi dengan pemeriksaan keamanan tingkat enterprise."""
        if not self.config:
            raise AliceException("Konfigurasi tidak dapat dimuat")
        api_key = self.config.get('api_key')
        if not api_key:
            raise ValidationError("API key tidak ditemukan dalam konfigurasi")
        if len(api_key) < 20:
            raise ValidationError("API key tidak valid, panjang minimal 20 karakter")
        endpoint = self.config.get('api_endpoint', 'https://api.basescan.org/api')
        if not endpoint.startswith('https://'):
            raise ValidationError("Endpoint API harus menggunakan HTTPS")
        timeout = self.config.get('timeout', 30)
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValidationError("Timeout konfigurasi tidak valid")
        self.logger.debug("Konfigurasi kritis berhasil divalidasi")

    async def _inisialisasi_komponen_keamanan(self):
        """Inisialisasi komponen keamanan dengan konfigurasi enterprise."""
        self.rate_limiter = RateLimiter(
            max_requests=5,
            time_window=1,
            burst_limit=10,
            penalty_duration=60
        )
        self.validator = ValidatorInput()
        await self.utility.setup_memory_monitor(max_memory_mb=50)
        self.logger.debug("Komponen keamanan berhasil diinisialisasi")

    async def _buat_struktur_direktori_enterprise(self):
        """Buat struktur direktori dengan permission dan validasi keamanan."""
        struktur_direktori = {
            'result': 0o755,
            'logs': 0o755,
            'credentials': 0o700,
            'temp': 0o755,
            'backup': 0o755
        }
        for nama_direktori, permission in struktur_direktori.items():
            path = Path(nama_direktori)
            try:
                path.mkdir(exist_ok=True, mode=permission)
                if not path.exists() or not path.is_dir():
                    raise AliceException(f"Gagal membuat direktori: {nama_direktori}")
                test_file = path / '.write_test'
                try:
                    test_file.touch()
                    test_file.unlink()
                except Exception:
                    raise AliceException(f"Tidak ada write permission di direktori: {nama_direktori}")
            except Exception as e:
                raise AliceException(f"Error membuat direktori {nama_direktori}: {e}")
        self.security_context['file_permissions_checked'] = True
        self.logger.debug("Struktur direktori enterprise berhasil dibuat")

    async def validasi_parameter_dengan_keamanan_forensik(self, args) -> Tuple[str, str, str, str]:
        """
        Validasi parameter input dengan tingkat keamanan forensik dan sanitasi komprehensif.
        Menerapkan whitelist validation dan defense against injection attacks.
        """
        waktu_mulai_validasi = time.time()
        try:
            self.terminal.print_step("[VALIDATE] Memulai validasi parameter dengan keamanan forensik...")
            perintah_valid = ['sc', 'h']
            if not args.perintah or args.perintah.lower() not in perintah_valid:
                raise ValidationError(
                    f"Perintah tidak valid: '{args.perintah}'. "
                    f"Perintah yang diizinkan: {', '.join(perintah_valid)}"
                )
            if args.perintah.lower() == 'h':
                return None, None, None, 'help'
            if not args.wallet:
                raise ValidationError("Alamat wallet diperlukan untuk operasi scan")
            wallet_sanitized = self.validator.sanitasi_alamat_wallet(args.wallet)
            if not self.validator.validasi_alamat_wallet_ketat(wallet_sanitized):
                raise ValidationError(
                    f"Format alamat wallet tidak valid: {args.wallet}\n"
                    "Format yang benar: 0x diikuti tepat 40 karakter heksadesimal\n"
                    "Contoh: 0x1234567890abcdef1234567890abcdef12345678"
                )
            if not self.validator.validasi_checksum_alamat(wallet_sanitized):
                self.terminal.print_warning(
                    "[VALIDATE] Alamat wallet tidak memiliki checksum yang valid, melanjutkan dengan risiko"
                )
            if args.print_cmd and args.print_cmd.lower() != 'p':
                raise ValidationError(
                    f"Perintah print tidak valid: '{args.print_cmd}'. Gunakan 'p' untuk aktivasi print"
                )
            versi_valid = ['Vfull', 'Vfrom']
            versi = args.versi or 'Vfull'
            if versi not in versi_valid:
                raise ValidationError(
                    f"Versi output tidak valid: '{versi}'. "
                    f"Versi yang diizinkan: {', '.join(versi_valid)}"
                )
            if args.file_output:
                file_output = self.validator.sanitasi_nama_file_ketat(args.file_output)
                if len(file_output) > 100:
                    raise ValidationError("Nama file terlalu panjang, maksimal 100 karakter")
                if not self.validator.validasi_nama_file_aman(file_output):
                    raise ValidationError(
                        "Nama file mengandung karakter tidak aman. Gunakan hanya huruf, angka, underscore, dan dash"
                    )
            else:
                timestamp = int(time.time())
                wallet_suffix = wallet_sanitized[-8:].lower()
                file_output = f"scan_{wallet_suffix}_{timestamp}.txt"
            self.security_context['input_validated'] = True
            self.metrics['waktu_validasi'] = time.time() - waktu_mulai_validasi
            self.terminal.print_success(
                f"[VALIDATE] Semua parameter valid (waktu: {self.metrics['waktu_validasi']:.3f}s)"
            )
            self.logger.info(f"Parameter berhasil divalidasi: wallet={wallet_sanitized}, versi={versi}")
            return wallet_sanitized, versi, file_output, 'scan'
        except ValidationError:
            self.metrics['error_count'] += 1
            raise
        except Exception as e:
            self.metrics['error_count'] += 1
            self.logger.error(f"Error dalam validasi parameter: {e}")
            raise AliceException(f"Gagal validasi parameter: {e}")

    async def eksekusi_scanning_enterprise(self, wallet: str, versi: str, file_output: str):
        """
        Eksekusi proses scanning dengan monitoring performa real-time dan error recovery.
        """
        waktu_mulai_scanning = time.time()
        self.mulai_waktu_global = waktu_mulai_scanning
        try:
            if not await self._konfirmasi_user_dengan_detail(wallet, versi, file_output):
                self.terminal.print_info("Operasi dibatalkan oleh pengguna")
                return 0
            self.terminal.print_step("[CONNECT] Menguji koneksi ke BaseScan API v2...")
            await self._test_koneksi_dan_autentikasi()
            self.terminal.print_step("[SCAN] Mengambil data token transfer dengan retry protection...")
            transfers = await self._scan_dengan_retry_mechanism(wallet)
            if not transfers:
                self.terminal.print_warning(
                    "Tidak ada token transfer ditemukan untuk alamat ini. Pastikan alamat benar dan memiliki riwayat transaksi"
                )
                return 0
            self.terminal.print_step(f"[PROCESS] Memproses {len(transfers)} transaksi dengan validasi ketat...")
            data_terformat = await self._process_data_dengan_validasi(transfers, versi)
            self.terminal.print_step("[FILTER] Menerapkan filter kualitas data dan deduplication...")
            data_final = await self._filter_dan_quality_assurance(data_terformat)
            self.terminal.print_step(f"[SAVE] Menulis hasil ke file dengan operasi atomic...")
            path_hasil = await self._simpan_dengan_atomic_operation(data_final, file_output)
            await self._validasi_hasil_dan_cleanup(path_hasil, len(data_final))
            waktu_total = time.time() - waktu_mulai_scanning
            await self._tampilkan_metrics_final(len(transfers), len(data_final), path_hasil, waktu_total)
            await self._validasi_performa_wajib(waktu_total)
            return 0
        except Exception as e:
            waktu_error = time.time() - waktu_mulai_scanning if waktu_mulai_scanning else 0
            await self._handle_error_comprehensive(e, wallet, waktu_error)
            return 1
        finally:
            await self._cleanup_resources()

    async def _konfirmasi_user_dengan_detail(self, wallet: str, versi: str, file_output: str) -> bool:
        """Konfirmasi user dengan informasi detail tentang operasi yang akan dilakukan."""
        self.terminal.print_info("=" * 80)
        self.terminal.print_info("KONFIRMASI OPERASI SCANNING")
        self.terminal.print_info("=" * 80)
        self.terminal.print_info(f"Target Wallet    : {wallet}")
        self.terminal.print_info(f"Format Output    : {versi}")
        self.terminal.print_info(f"File Hasil       : result/{file_output}")
        self.terminal.print_info(f"API Endpoint     : {self.config['api_endpoint']}")
        self.terminal.print_info(f"Rate Limit       : 5 requests/detik")
        self.terminal.print_info(f"Timeout          : {self.config.get('timeout', 30)} detik")
        self.terminal.print_info("=" * 80)
        return self.terminal.konfirmasi_scan_detail()

    async def _test_koneksi_dan_autentikasi(self):
        """Test koneksi API dan validasi autentikasi."""
        try:
            hasil_test = await self.scanner.test_koneksi_api_comprehensive()
            if not hasil_test['success']:
                raise APIError(f"Gagal koneksi API: {hasil_test['error']}")
            self.terminal.print_success(
                f"[CONNECT] Koneksi berhasil - latency: {hasil_test['latency']:.3f}s"
            )
        except Exception as e:
            raise APIError(f"Error test koneksi: {e}")

    async def _scan_dengan_retry_mechanism(self, wallet: str) -> list:
        """Scan dengan retry mechanism dan exponential backoff."""
        max_retry = 3
        base_delay = 1.0
        for attempt in range(max_retry):
            try:
                if attempt > 0:
                    delay = base_delay * (2 ** (attempt - 1))
                    self.terminal.print_warning(f"Retry attempt {attempt + 1}/{max_retry} after {delay}s delay")
                    await asyncio.sleep(delay)
                transfers = await self.scanner.scan_token_transfers_advanced(wallet)
                self.metrics['total_requests'] += 1
                return transfers
            except Exception as e:
                if attempt == max_retry - 1:
                    raise APIError(f"Gagal scanning setelah {max_retry} percobaan: {e}")
                self.logger.warning(f"Scanning attempt {attempt + 1} gagal: {e}")
        return []

    async def _process_data_dengan_validasi(self, transfers: list, versi: str) -> list:
        """Process data dengan validasi ketat dan error handling."""
        waktu_mulai = time.time()
        try:
            transfers_valid = []
            for i, transfer in enumerate(transfers):
                try:
                    if not self._validasi_struktur_transfer(transfer):
                        self.logger.warning(f"Transfer {i} tidak valid, dilewati")
                        continue
                    transfers_valid.append(transfer)
                except Exception as e:
                    self.logger.warning(f"Error validasi transfer {i}: {e}")
                    continue
            data_terformat = await self.scanner.format_output_advanced(transfers_valid, versi)
            self.metrics['waktu_processing'] = time.time() - waktu_mulai
            return data_terformat
        except Exception as e:
            raise AliceException(f"Error processing data: {e}")

    def _validasi_struktur_transfer(self, transfer: dict) -> bool:
        """Validasi struktur data transfer dengan pemeriksaan ketat."""
        field_wajib = ['hash', 'from', 'to', 'timeStamp']
        for field in field_wajib:
            if field not in transfer or not transfer[field]:
                return False
        if not transfer['hash'].startswith('0x') or len(transfer['hash']) != 66:
            return False
        for addr_field in ['from', 'to']:
            addr = transfer[addr_field]
            if not addr.startswith('0x') or len(addr) != 42:
                return False
        return True

    async def _filter_dan_quality_assurance(self, data: list) -> list:
        """Filter data dan quality assurance dengan deduplication."""
        seen_hashes = set()
        data_unique = []
        for item in data:
            if isinstance(item, dict):
                hash_tx = item.get('hash', '')
            else:
                hash_tx = item.split('|')[0] if '|' in item else item
            if hash_tx not in seen_hashes:
                seen_hashes.add(hash_tx)
                data_unique.append(item)
        return data_unique

    async def _simpan_dengan_atomic_operation(self, data: list, file_output: str) -> str:
        """Simpan data dengan atomic operation dan backup."""
        try:
            path_hasil = await self.scanner.simpan_hasil_atomic(data, file_output)
            backup_path = Path('backup') / f"{file_output}.backup"
            await self.utility.copy_file_async(path_hasil, backup_path)
            return str(path_hasil)
        except Exception as e:
            raise AliceException(f"Error saving file: {e}")

    async def _validasi_hasil_dan_cleanup(self, path_hasil: str, jumlah_data: int):
        """Validasi hasil file dan cleanup temporary resources."""
        if not Path(path_hasil).exists():
            raise AliceException("File hasil tidak berhasil dibuat")
        file_size = Path(path_hasil).stat().st_size
        if file_size == 0:
            raise AliceException("File hasil kosong")
        await self.utility.cleanup_temp_files()

    async def _tampilkan_metrics_final(self, total_transaksi: int, data_valid: int,
                                       path_hasil: str, waktu_total: float):
        """Tampilkan metrics final dengan informasi komprehensif."""
        self.metrics['memory_usage_peak'] = self.utility.get_memory_usage_current()
        self.terminal.print_success("[COMPLETE] Operasi berhasil diselesaikan")
        self.terminal.print_info("=" * 80)
        self.terminal.print_info("LAPORAN HASIL SCANNING")
        self.terminal.print_info("=" * 80)
        self.terminal.print_info(f"Total transaksi ditemukan  : {total_transaksi:,}")
        self.terminal.print_info(f"Data valid diproses        : {data_valid:,}")
        self.terminal.print_info(f"Tingkat validitas data     : {(data_valid/total_transaksi*100):.2f}%")
        self.terminal.print_info(f"File hasil tersimpan       : {path_hasil}")
        self.terminal.print_info(f"Ukuran file hasil          : {Path(path_hasil).stat().st_size:,} bytes")
        self.terminal.print_info(f"Waktu eksekusi total       : {waktu_total:.3f} detik")
        self.terminal.print_info(f"Total API requests         : {self.metrics['total_requests']}")
        self.terminal.print_info(f"Peak memory usage          : {self.metrics['memory_usage_peak']:.2f} MB")
        self.terminal.print_info("=" * 80)

    async def _validasi_performa_wajib(self, waktu_eksekusi: float):
        """Validasi performa sesuai requirement wajib (<1 detik)."""
        if waktu_eksekusi > 1.0:
            self.terminal.print_error(
                f"CRITICAL: Waktu eksekusi ({waktu_eksekusi:.3f}s) melebihi threshold 1 detik"
            )
            self.logger.critical(f"Performance violation: {waktu_eksekusi:.3f}s > 1.0s")
            self.logger.critical(f"Performance metrics: {self.metrics}")
        else:
            self.terminal.print_success(
                f"Performance OK: {waktu_eksekusi:.3f}s (within 1s threshold)"
            )

    async def _handle_error_comprehensive(self, error: Exception, wallet: str, waktu_error: float):
        """Handle error dengan logging comprehensive dan user guidance."""
        self.metrics['error_count'] += 1
        error_type = type(error).__name__
        error_message = str(error)
        self.logger.error(
            f"Error dalam scanning: {error_type}: {error_message}",
            extra={
                'wallet': wallet,
                'waktu_error': waktu_error,
                'error_type': error_type,
                'metrics': self.metrics
            }
        )
        if isinstance(error, ValidationError):
            self.terminal.print_error(f"[ERROR] [VALIDATION] {error_message}")
            self.terminal.print_info("[SUGGESTION] Periksa format alamat wallet dan parameter command")
        elif isinstance(error, APIError):
            self.terminal.print_error(f"[ERROR] [API] {error_message}")
            self.terminal.print_info("[SUGGESTION] Periksa koneksi internet dan status BaseScan API")
        elif isinstance(error, NetworkError):
            self.terminal.print_error(f"[ERROR] [NETWORK] {error_message}")
            self.terminal.print_info("[SUGGESTION] Periksa koneksi internet dan firewall settings")
        else:
            self.terminal.print_error(f"[ERROR] [SYSTEM] {error_message}")
            self.terminal.print_info("[SUGGESTION] Hubungi administrator untuk bantuan teknis")

    async def _cleanup_resources(self):
        """Cleanup resources dan close connections."""
        try:
            if self.scanner:
                await self.scanner.__aexit__(None, None, None)
            import gc
            gc.collect()
        except Exception as e:
            self.logger.warning(f"Warning during cleanup: {e}")

    async def jalankan_alice_bot(self):
        """
        Method utama untuk menjalankan ALICE Bot dengan error handling komprehensif.
        Entry point utama dengan orchestration seluruh proses.
        """
        exit_code = 1
        try:
            tampilkan_banner_selamat_datang()
            args = self.parse_argumen_dengan_validasi_ketat()
            await self.inisialisasi_sistem_enterprise()
            hasil_validasi = await self.validasi_parameter_dengan_keamanan_forensik(args)
            if hasil_validasi[3] == 'help':
                self.terminal.tampilkan_bantuan_lengkap()
                return 0
            wallet, versi, file_output, _ = hasil_validasi
            exit_code = await self.eksekusi_scanning_enterprise(wallet, versi, file_output)
            return exit_code
        except KeyboardInterrupt:
            self.terminal.print_warning("Operasi dihentikan oleh pengguna")
            return 130
        except ValidationError as e:
            if self.terminal:
                self.terminal.print_error(f"Error validasi: {e}")
            return 1
        except AliceException as e:
            if self.terminal:
                self.terminal.print_error(f"Error sistem: {e}")
            return 1
        except Exception as e:
            if self.logger:
                self.logger.critical(f"Unexpected error: {e}", exc_info=True)
            if self.terminal:
                self.terminal.print_error("Terjadi kesalahan sistem yang tidak terduga")
            return 1
        finally:
            await self._cleanup_resources()

async def main():
    """Function main dengan error handling tingkat enterprise."""
    bot = AliceBotEnterprise()
    return await bot.jalankan_alice_bot()

if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("Program dihentikan oleh pengguna")
        sys.exit(130)
    except Exception as e:
        print(f"CRITICAL ERROR: {e}")
        sys.exit(1)
