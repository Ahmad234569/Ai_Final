from langdetect import detect, DetectorFactory
from langdetect.lang_detect_exception import LangDetectException

# Set seed for reproducible results
DetectorFactory.seed = 0

def detect_language(text: str) -> str:
    """
    Detects the language of the provided text.
    Returns the ISO 639-1 code (e.g., 'en', 'ur', 'ko').
    Defaults to 'en' if detection fails.
    """
    try:
        if not text or len(text.strip()) == 0:
            return "en"
        lang = detect(text)
        return lang
    except LangDetectException:
        # Fallback to English if it fails (e.g., text is just numbers or symbols)
        return "en"

def is_supported_language(lang: str, supported: list) -> bool:
    return lang in supported
