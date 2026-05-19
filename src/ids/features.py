from __future__ import annotations

from dataclasses import dataclass

import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler


NUMERIC_FEATURES = [
    "duration",
    "src_bytes",
    "dst_bytes",
    "packets",
    "errors",
    "login_attempts",
]
CATEGORICAL_FEATURES = ["protocol"]
LABEL_COLUMN = "label"
FEATURE_COLUMNS = NUMERIC_FEATURES + CATEGORICAL_FEATURES


@dataclass(frozen=True)
class Dataset:
    features: pd.DataFrame
    labels: pd.Series | None = None


def load_dataset(path: str, require_labels: bool = True) -> Dataset:
    frame = pd.read_csv(path)
    validate_columns(frame, require_labels=require_labels)

    labels = frame[LABEL_COLUMN] if LABEL_COLUMN in frame.columns else None
    return Dataset(features=frame[FEATURE_COLUMNS].copy(), labels=labels)


def validate_columns(frame: pd.DataFrame, require_labels: bool) -> None:
    required = set(FEATURE_COLUMNS)
    if require_labels:
        required.add(LABEL_COLUMN)

    missing = sorted(required.difference(frame.columns))
    if missing:
        joined = ", ".join(missing)
        raise ValueError(f"CSV is missing required column(s): {joined}")


def build_preprocessor() -> ColumnTransformer:
    numeric_pipeline = Pipeline(
        steps=[
            ("scale", StandardScaler()),
        ]
    )
    categorical_pipeline = Pipeline(
        steps=[
            ("encode", OneHotEncoder(handle_unknown="ignore")),
        ]
    )

    return ColumnTransformer(
        transformers=[
            ("numeric", numeric_pipeline, NUMERIC_FEATURES),
            ("categorical", categorical_pipeline, CATEGORICAL_FEATURES),
        ]
    )
