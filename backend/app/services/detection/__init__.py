"""Detection engine package (Phase 5): signature + ML + YARA + autoencoder + UEBA."""

from app.services.detection.autoencoder import AutoencoderDetector
from app.services.detection.base import Detector
from app.services.detection.engine import DetectionEngine, detection_engine
from app.services.detection.ml import MLDetector
from app.services.detection.signature import SignatureDetector, match_record
from app.services.detection.ueba import UebaDetector
from app.services.detection.yara import YaraDetector
from app.services.detection.yara_engine import YaraRule, YaraRuleError, parse_rules

__all__ = [
    "AutoencoderDetector",
    "Detector",
    "DetectionEngine",
    "MLDetector",
    "SignatureDetector",
    "UebaDetector",
    "YaraDetector",
    "YaraRule",
    "YaraRuleError",
    "detection_engine",
    "match_record",
    "parse_rules",
]
