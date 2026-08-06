"""Unit tests for the ML retraining pipeline (Phase 6)."""

from __future__ import annotations

from pathlib import Path

from app.core.config import settings
from app.services.detection.ml import flow_features
from app.services.detection.retrain import (
    model_metadata,
    save_model,
    synthetic_flows,
    train_model_from_flows,
)


class TestSyntheticFlows:
    def test_generates_labeled_corpus(self) -> None:
        flows = synthetic_flows(normal=100, anomalous=100)
        assert len(flows) == 200
        assert all("length" in flow and "dst_port" in flow for flow in flows)

    def test_fixed_feature_dimension(self) -> None:
        flows = synthetic_flows(normal=10, anomalous=10)
        features = [flow_features(flow) for flow in flows]
        assert all(len(vector) == 5 for vector in features)


class TestTrainModel:
    def test_fits_isolation_forest(self) -> None:
        model = train_model_from_flows(
            synthetic_flows(normal=200, anomalous=200),
            n_estimators=50,
            contamination=0.1,
        )
        features = [flow_features(flow) for flow in synthetic_flows(normal=5, anomalous=5)]
        predictions = model.predict(features)
        assert len(predictions) == 10
        assert set(int(label) for label in predictions).issubset({-1, 1})


class TestSaveModel:
    def test_atomic_save_and_reload(self, tmp_path) -> None:
        from joblib import load

        model = train_model_from_flows(synthetic_flows(normal=100, anomalous=100), n_estimators=50)
        target = tmp_path / "model.joblib"
        result = save_model(model, target)
        assert result == target
        assert target.is_file()
        assert list(tmp_path.glob("*.tmp")) == []

        loaded = load(target)
        features = [flow_features(flow) for flow in synthetic_flows(normal=1, anomalous=1)]
        assert len(loaded.predict(features)) == 2


class TestModelMetadata:
    def test_missing_model(self, monkeypatch) -> None:
        monkeypatch.setattr(settings, "ML_MODEL_PATH", str(Path("C:/nope/model.joblib")))
        info = model_metadata()
        assert info["exists"] is False

    def test_existing_model(self, tmp_path, monkeypatch) -> None:
        target = tmp_path / "model.joblib"
        model = train_model_from_flows(synthetic_flows(normal=50, anomalous=50), n_estimators=25)
        save_model(model, target)
        monkeypatch.setattr(settings, "ML_MODEL_PATH", str(target))
        info = model_metadata()
        assert info["exists"] is True
        assert info["size_bytes"] > 0
        assert "modified_at" in info
