"""
Core Exceptions Module untuk ALICE Bot - Enterprise Error Handling System
Sistem exception handling komprehensif dengan hierarchical error classification.

Modul ini menangani:

- Hierarchical exception structure dengan inheritance-based classification
- Detailed error context preservation untuk debugging dan audit purposes
- Recovery suggestions dengan actionable guidance untuk users dan administrators
- Error severity levels dengan appropriate escalation mechanisms
- Structured error reporting dengan comprehensive information capture
- Thread-safe error handling dengan concurrent access considerations
- Performance impact tracking untuk error-related operations
- Security-conscious error messages yang tidak mengekspos sensitive information

Penulis: onex_dv
GitHub: https://github.com/onexdev
Lisensi: MIT Professional
Versi: 1.0.0
"""

import sys
import traceback
import time
from typing import Optional, Dict, Any, List, Union
from enum import Enum
import logging

class ErrorSeverity(Enum):
    """
    Enumeration untuk error severity levels dengan enterprise classification.
    """
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    FATAL = "FATAL"

class ErrorCategory(Enum):
    """
    Enumeration untuk error categories dengan business classification.
    """
    VALIDATION = "VALIDATION"
    API = "API"
    NETWORK = "NETWORK"
    CONFIGURATION = "CONFIGURATION"
    SECURITY = "SECURITY"
    FILESYSTEM = "FILESYSTEM"
    PERFORMANCE = "PERFORMANCE"
    BUSINESS_LOGIC = "BUSINESS_LOGIC"
    EXTERNAL_SERVICE = "EXTERNAL_SERVICE"
    SYSTEM = "SYSTEM"

class AliceException(Exception):
    """
    Base exception class untuk ALICE Bot dengan enterprise-level error handling.
    Menyediakan foundation untuk semua custom exceptions dengan comprehensive context.

    Fitur Enterprise:
    - Structured error information dengan metadata preservation
    - Recovery suggestions dengan actionable guidance
    - Error correlation dengan tracking untuk analysis
    - Security-conscious error message handling
    - Performance impact tracking
    - Thread-safe error context management
    - Audit trail integration untuk compliance requirements
    """

    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        category: ErrorCategory = ErrorCategory.SYSTEM,
        context: Optional[Dict[str, Any]] = None,
        recovery_suggestions: Optional[List[str]] = None,
        original_exception: Optional[Exception] = None,
        user_message: Optional[str] = None
    ):
        """
        Inisialisasi AliceException dengan comprehensive error context.

        Args:
            message: Technical error message untuk developers dan logs
            error_code: Unique error code untuk tracking dan documentation
            severity: Error severity level untuk escalation decisions
            category: Error category untuk classification dan routing
            context: Additional context information untuk debugging
            recovery_suggestions: List actionable recovery suggestions
            original_exception: Original exception jika ini adalah wrapper
            user_message: User-friendly message untuk end users
        """
        super().__init__(message)
        self.message = message
        self.error_code = error_code or self._generate_error_code()
        self.severity = severity
        self.category = category
        self.user_message = user_message or self._generate_user_message()
        self.context = context or {}
        self.recovery_suggestions = recovery_suggestions or []
        self.original_exception = original_exception
        self.timestamp = time.time()
        self.formatted_timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(self.timestamp))
        self.stack_trace = traceback.format_exc()
        import threading
        self.thread_id = threading.current_thread().ident
        self.thread_name = threading.current_thread().name
        self.performance_impact = self._assess_performance_impact()
        if not self.recovery_suggestions:
            self.recovery_suggestions = self._generate_recovery_suggestions()

    def _generate_error_code(self) -> str:
        """Generate unique error code berdasarkan exception type dan timestamp."""
        exception_name = self.__class__.__name__
        timestamp_str = str(int(self.timestamp))[-6:]
        return f"{exception_name.upper()}_{timestamp_str}"

    def _generate_user_message(self) -> str:
        """Generate user-friendly error message."""
        if self.severity in (ErrorSeverity.CRITICAL, ErrorSeverity.FATAL):
            return "Terjadi kesalahan sistem yang serius. Silakan hubungi administrator."
        if self.severity == ErrorSeverity.HIGH:
            return "Terjadi kesalahan yang memerlukan perhatian. Silakan coba lagi atau hubungi support."
        if self.severity == ErrorSeverity.MEDIUM:
            return "Terjadi kesalahan dalam operasi. Silakan periksa input dan coba lagi."
        return "Operasi tidak dapat diselesaikan. Silakan coba lagi."

    def _assess_performance_impact(self) -> str:
        """Assess performance impact berdasarkan severity dan category."""
        if self.severity in (ErrorSeverity.CRITICAL, ErrorSeverity.FATAL):
            return "HIGH"
        if self.category in (ErrorCategory.PERFORMANCE, ErrorCategory.NETWORK):
            return "MEDIUM"
        return "LOW"

    def _generate_recovery_suggestions(self) -> List[str]:
        """Generate recovery suggestions berdasarkan error type dan context."""
        suggestions = []
        if self.category == ErrorCategory.VALIDATION:
            suggestions += [
                "Periksa format input sesuai dengan spesifikasi",
                "Pastikan semua parameter yang diperlukan telah diisi",
                "Verifikasi bahwa data input berada dalam rentang yang valid"
            ]
        elif self.category == ErrorCategory.API:
            suggestions += [
                "Periksa koneksi internet dan coba lagi",
                "Verifikasi bahwa API key valid dan tidak expired",
                "Tunggu beberapa saat jika terjadi rate limiting"
            ]
        elif self.category == ErrorCategory.NETWORK:
            suggestions += [
                "Periksa koneksi internet",
                "Verifikasi pengaturan firewall dan proxy",
                "Coba lagi setelah beberapa saat"
            ]
        elif self.category == ErrorCategory.CONFIGURATION:
            suggestions += [
                "Periksa file konfigurasi untuk kesalahan",
                "Verifikasi bahwa semua pengaturan yang diperlukan sudah benar",
                "Restart aplikasi setelah mengubah konfigurasi"
            ]
        elif self.category == ErrorCategory.SECURITY:
            suggestions += [
                "Verifikasi credentials dan permissions",
                "Periksa log keamanan untuk indikasi masalah",
                "Hubungi administrator keamanan jika diperlukan"
            ]
        else:
            suggestions += [
                "Restart aplikasi dan coba lagi",
                "Periksa log sistem untuk informasi lebih detail",
                "Hubungi support jika masalah berlanjut"
            ]
        return suggestions

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception ke dictionary untuk serialization dan logging."""
        return {
            'error_code': self.error_code,
            'message': self.message,
            'user_message': self.user_message,
            'severity': self.severity.value,
            'category': self.category.value,
            'timestamp': self.timestamp,
            'formatted_timestamp': self.formatted_timestamp,
            'context': self.context,
            'recovery_suggestions': self.recovery_suggestions,
            'performance_impact': self.performance_impact,
            'thread_id': self.thread_id,
            'thread_name': self.thread_name,
            'original_exception': str(self.original_exception) if self.original_exception else None,
            'stack_trace': self.stack_trace
        }

    def get_user_display(self) -> str:
        """Get formatted error message untuk user display."""
        return f"[{self.error_code}] {self.user_message}"

    def get_technical_details(self) -> str:
        """Get technical error details untuk developers dan logs."""
        details = [
            f"Error Code: {self.error_code}",
            f"Message: {self.message}",
            f"Severity: {self.severity.value}",
            f"Category: {self.category.value}",
            f"Timestamp: {self.formatted_timestamp}"
        ]
        if self.context:
            details.append(f"Context: {self.context}")
        if self.recovery_suggestions:
            details.append("Recovery Suggestions:")
            details += [f"  {i+1}. {s}" for i, s in enumerate(self.recovery_suggestions)]
        return "\n".join(details)

class ValidationError(AliceException):
    """Exception untuk validation errors dengan specialized handling."""
    def __init__(
        self,
        message: str,
        field_name: Optional[str] = None,
        field_value: Optional[str] = None,
        validation_rule: Optional[str] = None,
        **kwargs
    ):
        context = kwargs.get('context', {})
        if field_name:
            context['field_name'] = field_name
        if field_value:
            if field_name and any(s in field_name.lower() for s in ['password', 'key', 'token', 'secret']):
                context['field_value'] = '***MASKED***'
            else:
                context['field_value'] = str(field_value)[:100]
        if validation_rule:
            context['validation_rule'] = validation_rule
        kwargs.update({
            'severity': ErrorSeverity.LOW,
            'category': ErrorCategory.VALIDATION,
            'context': context,
            'user_message': f"Input tidak valid: {message}"
        })
        super().__init__(message, **kwargs)

class APIError(AliceException):
    """Exception untuk API-related errors dengan detailed HTTP context."""
    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        response_body: Optional[str] = None,
        endpoint: Optional[str] = None,
        method: Optional[str] = None,
        **kwargs
    ):
        context = kwargs.get('context', {})
        if status_code:
            context['status_code'] = status_code
        if endpoint:
            context['endpoint'] = endpoint
        if method:
            context['method'] = method
        if response_body:
            context['response_body'] = (
                response_body[:500] + '...' if len(response_body) > 500 else response_body
            )
        severity = ErrorSeverity.MEDIUM
        if status_code and status_code >= 500:
            severity = ErrorSeverity.HIGH
        elif status_code == 429:
            severity = ErrorSeverity.MEDIUM
        elif status_code and status_code >= 400:
            severity = ErrorSeverity.LOW
        kwargs.update({
            'severity': severity,
            'category': ErrorCategory.API,
            'context': context,
            'user_message': f"Terjadi kesalahan koneksi API: {message}"
        })
        super().__init__(message, **kwargs)

class NetworkError(AliceException):
    """Exception untuk network-related errors dengan connection context."""
    def __init__(
        self,
        message: str,
        timeout_duration: Optional[float] = None,
        retry_count: Optional[int] = None,
        **kwargs
    ):
        context = kwargs.get('context', {})
        if timeout_duration:
            context['timeout_duration'] = timeout_duration
        if retry_count:
            context['retry_count'] = retry_count
        kwargs.update({
            'severity': ErrorSeverity.MEDIUM,
            'category': ErrorCategory.NETWORK,
            'context': context,
            'user_message': "Terjadi masalah koneksi jaringan. Periksa koneksi internet Anda."
        })
        super().__init__(message, **kwargs)

class SecurityError(AliceException):
    """Exception untuk security-related errors dengan security context."""
    def __init__(
        self,
        message: str,
        security_context: Optional[str] = None,
        **kwargs
    ):
        context = kwargs.get('context', {})
        if security_context:
            context['security_context'] = security_context
        kwargs.update({
            'severity': ErrorSeverity.HIGH,
            'category': ErrorCategory.SECURITY,
            'context': context,
            'user_message': "Terjadi masalah keamanan. Hubungi administrator."
        })
        super().__init__(message, **kwargs)

class ConfigurationError(AliceException):
    """Exception untuk configuration-related errors dengan config context."""
    def __init__(
        self,
        message: str,
        config_file: Optional[str] = None,
        config_section: Optional[str] = None,
        config_key: Optional[str] = None,
        **kwargs
    ):
        context = kwargs.get('context', {})
        if config_file:
            context['config_file'] = config_file
        if config_section:
            context['config_section'] = config_section
        if config_key:
            context['config_key'] = config_key
        kwargs.update({
            'severity': ErrorSeverity.HIGH,
            'category': ErrorCategory.CONFIGURATION,
            'context': context,
            'user_message': "Terjadi masalah konfigurasi. Periksa pengaturan aplikasi."
        })
        super().__init__(message, **kwargs)

class PerformanceError(AliceException):
    """Exception untuk performance-related errors dengan performance context."""
    def __init__(
        self,
        message: str,
        operation_duration: Optional[float] = None,
        performance_threshold: Optional[float] = None,
        resource_usage: Optional[Dict[str, Any]] = None,
        **kwargs
    ):
        context = kwargs.get('context', {})
        if operation_duration:
            context['operation_duration'] = operation_duration
        if performance_threshold:
            context['performance_threshold'] = performance_threshold
        if resource_usage:
            context['resource_usage'] = resource_usage
        kwargs.update({
            'severity': ErrorSeverity.MEDIUM,
            'category': ErrorCategory.PERFORMANCE,
            'context': context,
            'user_message': "Operasi berjalan lebih lambat dari yang diharapkan."
        })
        super().__init__(message, **kwargs)

class FileSystemError(AliceException):
    """Exception untuk filesystem-related errors dengan file context."""
    def __init__(
        self,
        message: str,
        file_path: Optional[str] = None,
        operation: Optional[str] = None,
        permissions: Optional[str] = None,
        **kwargs
    ):
        context = kwargs.get('context', {})
        if file_path:
            context['file_path'] = file_path
        if operation:
            context['operation'] = operation
        if permissions:
            context['permissions'] = permissions
        kwargs.update({
            'severity': ErrorSeverity.MEDIUM,
            'category': ErrorCategory.FILESYSTEM,
            'context': context,
            'user_message': "Terjadi masalah dalam mengakses file sistem."
        })
        super().__init__(message, **kwargs)

def handle_exception_comprehensive(
    exception: Exception,
    logger: Optional[logging.Logger] = None,
    context: Optional[Dict[str, Any]] = None
) -> AliceException:
    """
    Comprehensive exception handler yang mengkonversi standard exceptions ke AliceException.

    Args:
        exception: Exception yang akan di-handle
        logger: Logger instance untuk logging
        context: Additional context information

    Returns:
        AliceException: Wrapped exception dengan comprehensive context
    """
    if isinstance(exception, AliceException):
        return exception

    exception_mapping = {
        ValueError: ValidationError,
        FileNotFoundError: FileSystemError,
        PermissionError: FileSystemError,
        ConnectionError: NetworkError,
        TimeoutError: NetworkError,
        OSError: FileSystemError,
    }
    custom_cls = exception_mapping.get(type(exception), AliceException)
    custom_exc = custom_cls(
        message=str(exception),
        original_exception=exception,
        context=context or {}
    )
    if logger:
        logger.error(f"Exception handled: {custom_exc.get_technical_details()}")
    return custom_exc

def create_error_context(
    operation: str = None,
    user_input: Dict[str, Any] = None,
    system_state: Dict[str, Any] = None
) -> Dict[str, Any]:
    """
    Create comprehensive error context untuk detailed error reporting.

    Args:
        operation: Operation yang sedang dilakukan
        user_input: User input yang terkait
        system_state: System state information

    Returns:
        Dict: Comprehensive error context
    """
    context = {
        'timestamp': time.time(),
        'python_version': sys.version,
        'platform': sys.platform
    }
    if operation:
        context['operation'] = operation
    if user_input:
        sanitized = {}
        for k, v in user_input.items():
            if any(s in k.lower() for s in ['password', 'key', 'token', 'secret']):
                sanitized[k] = '***MASKED***'
            else:
                sanitized[k] = str(v)[:100]
        context['user_input'] = sanitized
    if system_state:
        context['system_state'] = system_state
    return context

if __name__ == "__main__":
    logger = logging.getLogger("test")
    try:
        raise ValidationError(
            "Invalid wallet address format",
            field_name="wallet_address",
            field_value="invalid_address",
            validation_rule="Must start with 0x and be 42 characters"
        )
    except ValidationError as e:
        print(f"ValidationError: {e.get_user_display()}")
        print(f"Technical Details:\n{e.get_technical_details()}")

    try:
        raise APIError(
            "API request failed",
            status_code=429,
            endpoint="https://api.etherscan.io/v2/api",
            method="GET"
        )
    except APIError as e:
        print(f"\nAPIError: {e.get_user_display()}")
        print(f"Technical Details:\n{e.get_technical_details()}")

    try:
        raise ValueError("Standard Python exception")
    except Exception as e:
        handled = handle_exception_comprehensive(e, logger)
        print(f"\nHandled Exception: {handled.get_user_display()}")
