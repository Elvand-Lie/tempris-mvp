from enum import Enum
from fastapi import HTTPException

class EDIPDecision(str, Enum):
    MITIGATE = "mitigate"
    ACCEPT = "accept"
    TRANSFER = "transfer"
    IGNORE = "ignore"

def validate_edip_transition(current_decision: str | None, requested_decision: str):
    """Enforces transition constraints.
    - 'ignore' is terminal. Transitioning away from 'ignore' to any other decision is forbidden.
    - Other transitions are allowed.
    """
    if current_decision == "ignore" and requested_decision != "ignore":
        raise HTTPException(
            status_code=409,
            detail={
                "error": {
                    "code": "INVALID_STATE_TRANSITION",
                    "message": "Cannot transition out of terminal state 'ignore'."
                }
            }
        )
