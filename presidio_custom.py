from presidio_analyzer import AnalyzerEngine, RecognizerRegistry, PatternRecognizer, Pattern
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

class PresidioCustom:
    def __init__(self, pii_config: dict = None):
        self.config = pii_config or {}
        
        # Initialize NLP Engine
        provider = NlpEngineProvider(nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}]
        })
        nlp_engine = provider.create_engine()
        
        # Initialize Analyzer and Registry
        self.registry = RecognizerRegistry()
        self.registry.load_predefined_recognizers()
        
        # Add Custom Recognizers
        self._add_custom_recognizers()
        
        self.analyzer = AnalyzerEngine(registry=self.registry, nlp_engine=nlp_engine, supported_languages=["en"])
        self.anonymizer = AnonymizerEngine()

    def _add_custom_recognizers(self):
        # 1. CNIC Recognizer: Pattern 12345-1234567-1
        cnic_pattern = Pattern(name="cnic_pattern", regex=r"\b\d{5}-\d{7}-\d{1}\b", score=0.5)
        cnic_recognizer = PatternRecognizer(
            supported_entity="CNIC",
            patterns=[cnic_pattern],
            context=["cnic", "id card", "identity", "national id"]
        )
        self.registry.add_recognizer(cnic_recognizer)
        
        # 2. API Key Recognizer
        # E.g., sk-... or any 32+ char alphanumeric string
        api_key_pattern = Pattern(name="api_key_pattern", regex=r"\b(?:sk-[a-zA-Z0-9-]{10,}|[a-zA-Z0-9]{32,})\b", score=0.4)
        api_key_recognizer = PatternRecognizer(
            supported_entity="API_KEY",
            patterns=[api_key_pattern],
            context=["api key", "token", "secret", "bearer"]
        )
        self.registry.add_recognizer(api_key_recognizer)
        
        # 3. Student ID Recognizer: Pattern like FA21-BCS-001 or similar format
        student_id_pattern = Pattern(name="student_id_pattern", regex=r"\b[A-Z]{2}\d{2}-[A-Z]{3}-\d{3,4}\b", score=0.6)
        student_id_recognizer = PatternRecognizer(
            supported_entity="STUDENT_ID",
            patterns=[student_id_pattern],
            context=["student id", "roll number", "registration"]
        )
        self.registry.add_recognizer(student_id_recognizer)

    def analyze_and_anonymize(self, text: str):
        if not text:
            return {"score": 0.0, "safe_text": "", "entities": []}
            
        # Composite entity detection & Context aware scoring is handled by Presidio natively when context words match.
        # We also enforce confidence thresholding (e.g. > 0.4)
        results = self.analyzer.analyze(
            text=text,
            language="en",
            entities=["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "CNIC", "API_KEY", "STUDENT_ID"],
            score_threshold=0.4,
            return_decision_process=False
        )
        
        # Build anonymization operators mapping
        operators = {
            "PERSON": OperatorConfig("replace", {"new_value": "<PERSON>"}),
            "EMAIL_ADDRESS": OperatorConfig("replace", {"new_value": "<EMAIL>"}),
            "PHONE_NUMBER": OperatorConfig("replace", {"new_value": "<PHONE>"}),
            "CNIC": OperatorConfig("replace", {"new_value": "<CNIC>"}),
            "API_KEY": OperatorConfig("replace", {"new_value": "<API_KEY>"}),
            "STUDENT_ID": OperatorConfig("replace", {"new_value": "<STUDENT_ID>"})
        }
        
        # Anonymize
        anonymized_result = self.anonymizer.anonymize(
            text=text,
            analyzer_results=results,
            operators=operators
        )
        
        entities_list = []
        max_score = 0.0
        for r in results:
            if r.score > max_score:
                max_score = r.score
            entities_list.append({
                "type": r.entity_type,
                "text": text[r.start:r.end],
                "score": round(r.score, 4)
            })
            
        return {
            "score": max_score, # Risk score based on PII detection confidence
            "safe_text": anonymized_result.text,
            "entities": entities_list
        }
