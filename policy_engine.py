class PolicyEngine:
    def __init__(self, config: dict):
        self.config = config.get("policy", {})
        self.rule_weight = self.config.get("rule_weight", 1.0)
        self.semantic_weight = self.config.get("semantic_weight", 1.0)
        self.pii_weight = self.config.get("pii_weight", 0.8)
        self.secret_weight = self.config.get("secret_weight", 1.0)
        self.block_threshold = self.config.get("block_threshold", 0.8)
        self.mask_threshold = self.config.get("mask_threshold", 0.1)

    def evaluate(self, rule_score: float, semantic_score: float, pii_score: float) -> tuple:
        """
        Calculates final risk and decision based on the scores.
        Formula: final_risk = max(rule_score * rule_weight, semantic_score * semantic_weight) + pii_score * pii_weight
        (Secret weight can be folded into PII if API keys/passwords are treated as secrets)
        """
        # Calculate risk components
        injection_risk = max(rule_score * self.rule_weight, semantic_score * self.semantic_weight)
        data_risk = pii_score * self.pii_weight
        
        # Calculate final risk
        final_risk = injection_risk + data_risk
        
        # Determine decision
        if injection_risk >= self.block_threshold:
            decision = "BLOCK"
        elif pii_score >= self.mask_threshold:
            # If PII is detected, we MASK it.
            # We only BLOCK if there's also a high injection risk (e.g. > 0.6)
            if injection_risk >= 0.6:
                decision = "BLOCK"
            else:
                decision = "MASK"
        elif final_risk >= self.block_threshold:
            decision = "BLOCK"
        else:
            decision = "ALLOW"
            
        return final_risk, decision
