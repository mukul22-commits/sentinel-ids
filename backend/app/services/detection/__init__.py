"""Detection engine package (Phase 5): signature + ML detectors."""

from app.services.detection.base import Detector
from app.services.detection.engine import DetectionEngine, detection_engine
from app.services.detection.ml import MLDetector
from app.services.detection.signature import SignatureDetector, match_record

__all__ = [
    "Detector",
    "DetectionEngine",
    "MLDetector",
    "SignatureDetector",
    "detection_engine",
    "match_record",
]
