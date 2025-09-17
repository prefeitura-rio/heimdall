"""
Custom exceptions for Heimdall Admin Service.
"""


class ServiceUnavailableError(Exception):
    """
    Exception raised when an external service is unavailable.
    Should result in HTTP 503 Service Unavailable response.
    """

    def __init__(self, service_name: str, original_error: Exception | None = None):
        self.service_name = service_name
        self.original_error = original_error
        message = f"Service '{service_name}' is currently unavailable"
        if original_error:
            message += f": {str(original_error)}"
        super().__init__(message)


class CerbosUnavailableError(ServiceUnavailableError):
    """
    Exception raised when Cerbos authorization service is unavailable.
    """

    def __init__(self, original_error: Exception | None = None):
        super().__init__("Cerbos Authorization Service", original_error)
