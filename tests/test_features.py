import pandas as pd
import pytest

from src.ids.features import FEATURE_COLUMNS, validate_columns
from src.ids.train import build_nsl_kdd_preprocessor, load_nsl_kdd_dataset


def test_validate_columns_accepts_complete_detection_frame():
    frame = pd.DataFrame(columns=FEATURE_COLUMNS)

    validate_columns(frame, require_labels=False)


def test_validate_columns_reports_missing_columns():
    frame = pd.DataFrame(columns=["duration", "protocol"])

    with pytest.raises(ValueError, match="dst_bytes"):
        validate_columns(frame, require_labels=False)


def test_load_nsl_kdd_dataset_converts_labels_to_binary_classes(tmp_path):
    rows = [
        "0,tcp,http,SF,181,5450,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,8,8,0.00,0.00,0.00,0.00,1.00,0.00,0.00,9,9,1.00,0.00,0.11,0.00,0.00,0.00,0.00,0.00,normal,21",
        "0,tcp,private,S0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,229,10,1.00,1.00,0.00,0.00,0.04,0.06,0.00,255,10,0.04,0.06,0.00,0.00,1.00,1.00,0.00,0.00,neptune,21",
    ]
    dataset = tmp_path / "kdd.csv"
    dataset.write_text("\n".join(rows), encoding="utf-8")

    features, labels = load_nsl_kdd_dataset(str(dataset))

    assert "label" not in features.columns
    assert "difficulty" not in features.columns
    assert labels.tolist() == ["normal", "attack"]


def test_nsl_kdd_preprocessor_scales_and_encodes_features(tmp_path):
    rows = [
        "0,tcp,http,SF,181,5450,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,8,8,0.00,0.00,0.00,0.00,1.00,0.00,0.00,9,9,1.00,0.00,0.11,0.00,0.00,0.00,0.00,0.00,normal,21",
        "0,udp,domain_u,SF,44,139,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2,2,0.00,0.00,0.00,0.00,1.00,0.00,0.00,255,254,1.00,0.01,0.00,0.00,0.00,0.00,0.00,0.00,normal,18",
        "0,tcp,private,S0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,229,10,1.00,1.00,0.00,0.00,0.04,0.06,0.00,255,10,0.04,0.06,0.00,0.00,1.00,1.00,0.00,0.00,neptune,21",
    ]
    dataset = tmp_path / "kdd.csv"
    dataset.write_text("\n".join(rows), encoding="utf-8")
    features, _ = load_nsl_kdd_dataset(str(dataset))

    transformed = build_nsl_kdd_preprocessor(features).fit_transform(features)

    assert transformed.shape[0] == 3
    assert transformed.shape[1] > features.shape[1]
