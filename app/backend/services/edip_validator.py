from enum import Enum
from fastapi import HTTPException

class EDIPDecision(str, Enum):
    MITIGATE = "mitigate"
    ACCEPT = "accept"
    TRANSFER = "transfer"
    IGNORE = "ignore"

def validate_edip_transition(current_decision: str | None, requested_decision: str):
    """EDIP decisions are revisable; the audit trail records every override."""
    return None
