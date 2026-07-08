"""Shared mapping from an AWS exception to a check Status."""
from botocore.exceptions import ClientError

from scanner.models import Status


def status_from_error(exc: Exception, not_configured_codes=()) -> Status:
    """Classify an exception raised while evaluating a security check.

    A recognized "resource not configured" error code means the control is
    genuinely absent, so the resource is non-compliant → FAIL. Any other error
    (AccessDenied, throttling, transient network failure) means the check could
    not be evaluated → ERROR, so it is never reported as a false FAIL.
    """
    if isinstance(exc, ClientError):
        code = exc.response.get("Error", {}).get("Code", "")
        if code in not_configured_codes:
            return Status.FAIL
    return Status.ERROR
