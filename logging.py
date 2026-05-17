import logging
import json
import os
from datetime import datetime

# Setup logger
logger = logging.getLogger("LLMSecurityGateway")
logger.setLevel(logging.INFO)

# File handler
log_dir = "logs"
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

file_handler = logging.FileHandler(f"logs/audit_{datetime.now().strftime('%Y%m%d')}.log")
file_handler.setLevel(logging.INFO)

# Console handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

logger.addHandler(file_handler)
logger.addHandler(console_handler)


def log_audit_event(
    input_id: str,
    language: str,
    rule_score: float,
    semantic_score: float,
    pii_entities: list,
    final_risk: float,
    decision: str,
    reason_codes: list,
    latency_ms: int,
    original_prompt: str,
    safe_text: str = None
):
    """
    Logs an auditable event in JSON format.
    """
    event = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "input_id": input_id,
        "language": language,
        "rule_score": round(rule_score, 4),
        "semantic_score": round(semantic_score, 4),
        "pii_entities": pii_entities,
        "final_risk": round(final_risk, 4),
        "decision": decision,
        "reason_codes": reason_codes,
        "latency_ms": latency_ms,
        "safe_text_preview": safe_text[:50] + "..." if safe_text and len(safe_text) > 50 else safe_text
    }
    
    # We do not log the full original prompt to prevent exfiltration through logs,
    # but we can log a short hash or masked version if needed. Here we keep it omitted for safety.
    
    logger.info(json.dumps(event))

