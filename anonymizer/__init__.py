"""AnonApp: biblioteca de anonimização de dados para conformidade com a LGPD."""
from .crypto import generate_secret, key_fingerprint
from .detection import detect_dataframe
from .engine import Config, Result, Rule, run
from .risk import assess, class_size_distribution, enforce_k
from .techniques import TECHNIQUES, Context

__all__ = [
    "TECHNIQUES", "Config", "Context", "Result", "Rule", "assess", "class_size_distribution",
    "detect_dataframe", "enforce_k", "generate_secret", "key_fingerprint", "run",
]
