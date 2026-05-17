from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
import yaml
import time
import os

from app.utils.language import detect_language, is_supported_language
from app.utils.logging import log_audit_event
from app.detectors.rule_detector import RuleDetector
from app.detectors.semantic_detector import SemanticDetector
from app.pii.presidio_custom import PresidioCustom
from app.policy.policy_engine import PolicyEngine

app = FastAPI(title="LLM Security Gateway")

@app.get("/")
def read_root():
    return FileResponse(os.path.join(os.path.dirname(__file__), "static", "index.html"))

# Load Configuration
config_path = os.path.join(os.path.dirname(__file__), "..", "config", "gateway_config.yaml")
with open(config_path, "r") as f:
    config = yaml.safe_load(f)

# Initialize Components
rule_detector = RuleDetector()
semantic_detector = SemanticDetector(
    model_name=config.get("semantic", {}).get("model_name", "all-MiniLM-L6-v2"),
    threshold=config.get("semantic", {}).get("similarity_threshold", 0.75)
)
presidio = PresidioCustom(pii_config=config.get("pii", {}))
policy_engine = PolicyEngine(config=config)

class PromptRequest(BaseModel):
    input_id: str
    prompt: str

@app.post("/analyze")
async def analyze_prompt(request: PromptRequest):
    start_time = time.time()
    
    # 1. Language Detection
    lang = detect_language(request.prompt)
    
    # 2. Rule-Based Analysis
    rule_score = rule_detector.analyze(request.prompt)
    rule_reasons = rule_detector.get_reason(request.prompt)
    
    # 3. Semantic Analysis
    semantic_score = semantic_detector.analyze(request.prompt)
    semantic_reasons = semantic_detector.get_reason(semantic_score)
    
    # 4. PII / Presidio Analysis
    pii_results = presidio.analyze_and_anonymize(request.prompt)
    pii_score = pii_results["score"]
    
    # 5. Policy Engine Decision
    final_risk, decision = policy_engine.evaluate(rule_score, semantic_score, pii_score)
    
    # Consolidate Reason Codes
    reason_codes = rule_reasons + semantic_reasons
    if pii_score >= policy_engine.mask_threshold:
        reason_codes.append("PII_DETECTED")
        
    # Determine safe_text output
    safe_text = None
    if decision == "MASK":
        safe_text = pii_results["safe_text"]
    elif decision == "ALLOW":
        safe_text = request.prompt
        
    latency_ms = int((time.time() - start_time) * 1000)
    
    # 6. Audit Logging
    log_audit_event(
        input_id=request.input_id,
        language=lang,
        rule_score=rule_score,
        semantic_score=semantic_score,
        pii_entities=pii_results["entities"],
        final_risk=final_risk,
        decision=decision,
        reason_codes=reason_codes,
        latency_ms=latency_ms,
        original_prompt=request.prompt,
        safe_text=safe_text
    )
    
    # Prepare API Output Format
    response = {
        "input_id": request.input_id,
        "language": lang,
        "rule_score": round(rule_score, 4),
        "semantic_score": round(semantic_score, 4),
        "pii_entities": pii_results["entities"],
        "final_risk": round(final_risk, 4),
        "decision": decision,
        "safe_text": safe_text,
        "reason_codes": reason_codes,
        "latency_ms": latency_ms
    }
    
    return response

@app.get("/health")
def health_check():
    return {"status": "healthy"}
