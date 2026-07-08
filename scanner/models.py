from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"


class Status(str, Enum):
    FAIL = "FAIL"
    PASS = "PASS"
    ERROR = "ERROR"   # check could not be evaluated (e.g. AccessDenied, throttling)


@dataclass
class Finding:
    check_id:    str          # e.g. "S3-001"
    title:       str          # e.g. "S3 bucket has public access enabled"
    resource:    str          # e.g. "my-bucket"
    service:     str          # e.g. "S3"
    severity:    Severity
    status:      Status
    region:      str
    remediation: str          # human-readable fix description
    timestamp:   str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "check_id":    self.check_id,
            "title":       self.title,
            "resource":    self.resource,
            "service":     self.service,
            "severity":    self.severity.value,
            "status":      self.status.value,
            "region":      self.region,
            "remediation": self.remediation,
            "timestamp":   self.timestamp,
        }
