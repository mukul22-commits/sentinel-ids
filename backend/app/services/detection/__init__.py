"""Detection engine package (Phase 5): signature + ML + YARA + autoencoder."""

from app.services.detection.autoencoder import AutoencoderDetector
from app.services.detection.base import Detector
from app.services.detection.engine import DetectionEngine, detection_engine
from app.services.detection.ml import MLDetector
from app.services.detection.signature import SignatureDetector, match_record
from app.services.detection.yara import YaraDetector
from app.services.detection.yara_engine import YaraRule, YaraRuleError, parse_rules

__all__ = [
    "AutoencoderDetector",
    "Detector",
    "DetectionEngine",
    "MLDetector",
    "SignatureDetector",
    "YaraDetector",
    "YaraRule",
    "YaraRuleError",
    "detection_engine",
    "match_record",
    "parse_rules",
]
