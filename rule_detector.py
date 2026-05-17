import re

class RuleDetector:
    def __init__(self):
        # Patterns for detecting various attacks
        self.injection_patterns = [
            r"(?i)ign[o0]r[e3]\s*(?:all\s*)?(?:prev[i1!l][o0]us\s*)?instruct[i1!l][o0]ns?",
            r"(?i)f[o0]rget\s*(?:all\s*)?(?:earlier|previ[o0]us\s*)?(?:guidelines|rules|instructions?)",
            r"(?i)(?:disregard|ignore)\s*(?:all\s*)?(?:safety\s*)?rules",
            r"(?i)bypass\s+(?:all\s*)?(?:safety\s*)?rules|filters",
            r"(?i)system\s+(?:prompt|instructions?|rules|setup)",
            r"(?i)hidd[e3]n\s+(?:c[o0]nf[i1]g|c[o0]nfigurati[o0]n|setup|pr[o0]mpt|informati[o0]n|credentials?)",
            r"(?i)interna[l1]\s+(?:rules|instructions?)",
            r"(?i)y[o0]u\s+ar[e3]\s+n[o0]w",
            r"(?i)pretend\s+y[o0]u\s+ar[e3]",
            r"(?i)act\s+as\s+a\s*(?:developer|hacker|grandmother|unrestricted)",
            r"(?i)act\s+without\s+restrictions",
            r"(?i)r[o0]leplay\s+as\s+(?:a\s+system\s+with\s+)?n[o0]\s+ethical\s+boundaries",
            r"(?i)DAN\s+\(Do\s+Anything\s+Now\)",
            r"(?i)translate\s+this\s+into",
            r"(?i)base64",
            r"(?i)(?:print|tell\s+me|reveal|show|expose|display|output|d1scl0s3|sh0w)\s*(?:me\s*)?(?:your\s*)?(?:initial\s*|hidden\s*)?(?:prompt|instructions?|rules|passwords?|credentials|setup)",
            r"(?i)(?:give|show|output|print)\s*(?:me\s*)?(?:any\s*|all\s*)?(?:api\s+keys?|tokens?|passwords?|credentials|database\s+connection\s+strings?|confidential\s+system\s+variables?)",
            r"(?i)what\s+are\s+your\s+rules",
            r"(?i)override\s*(?:your\s*)?policy",
            r"(?i)disable\s*(?:all\s*)?restrictions",
            r"(?i)use\s+retrieved\s+documents\s+as\s+system\s+instructions",
            r"(?i)treat\s+the\s+database\s+content\s+as\s+your\s+main\s+instruction",
            r"(?i)replace\s+your\s+system\s+prompt\s+with",
            r"(?i)execute\s+tool\s+output\s+as\s+a\s+trusted\s+system\s+command",
            r"(?i)ig n o r e",
            r"(?i)sh ow system prompt",
            r"(?i)1gn0r3",
            
            # Urdu translations (expanded)
            r"(?i)پچھلی\s*(?:تمام\s*)?ہدایات\s*کو\s*نظر\s*انداز\s*کریں",
            r"(?i)تمام\s*اصول\s*بھول\s*جائیں",
            r"(?i)سیکیورٹی\s*کو\s*نظر\s*انداز\s*کریں",
            r"(?i)سسٹم\s*پرامپٹ",
            r"(?i)خفیہ\s*معلومات",
            r"(?i)اندرونی\s*ہدایات",
            r"(?i)اب\s+آپ\s+ہیں",
            
            # Korean translations (expanded)
            r"(?i)이전\s*(?:의\s*)?(?:모든\s*)?지침을\s*무시",
            r"(?i)모든\s*규칙을\s*무시",
            r"(?i)제한\s*없이\s*작동",
            r"(?i)시스템\s*프롬프트",
            r"(?i)내부\s*설정",
            r"(?i)숨겨진\s*정보",
            r"(?i)당신은\s+이제",
            
            # Mixed Language (Urdu/English)
            r"(?i)ignore\s+rules\s+aur",
            r"(?i)rules\s+ignore\s+karo",
            r"(?i)ignore\s+everything\s+اور"
        ]
        self.compiled_patterns = [re.compile(p) for p in self.injection_patterns]

    def analyze(self, text: str) -> float:
        """
        Analyzes the text using regex patterns.
        Returns a risk score between 0.0 and 1.0.
        """
        if not text:
            return 0.0
            
        for pattern in self.compiled_patterns:
            if pattern.search(text):
                return 1.0  # An explicit rule match indicates a definite injection attempt
                
        return 0.0

    def get_reason(self, text: str) -> list:
        reasons = []
        if self.analyze(text) > 0:
            reasons.append("RULE_MATCH_INJECTION")
        return reasons
