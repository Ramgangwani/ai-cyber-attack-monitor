from __future__ import annotations

import argparse
from pathlib import Path

import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from .features import build_preprocessor, load_dataset


DEFAULT_NSL_KDD_DATA_PATH = "data/KDDTrain+.txt.zip"
DEFAULT_MODEL_PATH = "models/ids_model.joblib"


NSL_KDD_COLUMNS = [
    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "land",
    "wrong_fragment",
    "urgent",
    "hot",
    "num_failed_logins",
    "logged_in",
    "num_compromised",
    "root_shell",
    "su_attempted",
    "num_root",
    "num_file_creations",
    "num_shells",
    "num_access_files",
    "num_outbound_cmds",
    "is_host_login",
    "is_guest_login",
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "srv_diff_host_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate",
    "dst_host_srv_serror_rate",
    "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
    "label",
    "difficulty",
]


NSL_KDD_CATEGORICAL_COLUMNS = ["protocol_type", "service", "flag"]


def normalize_attack_label(label: object) -> str:
    cleaned = str(label).strip().lower().rstrip(".")
    return "normal" if cleaned == "normal" else "attack"


def load_nsl_kdd_dataset(data_path: str) -> tuple[pd.DataFrame, pd.Series]:
    frame = pd.read_csv(data_path)

    if "label" not in frame.columns:
        frame = pd.read_csv(data_path, header=None)
        if frame.shape[1] == len(NSL_KDD_COLUMNS):
            frame.columns = NSL_KDD_COLUMNS
        elif frame.shape[1] == len(NSL_KDD_COLUMNS) - 1:
            frame.columns = NSL_KDD_COLUMNS[:-1]
        else:
            raise ValueError(
                "NSL-KDD CSV must contain 42 columns or 43 columns including difficulty."
            )

    if "label" not in frame.columns:
        raise ValueError("NSL-KDD data must include a label column.")

    labels = frame["label"].map(normalize_attack_label)
    features = frame.drop(columns=["label", "difficulty"], errors="ignore")

    for column in features.columns.difference(NSL_KDD_CATEGORICAL_COLUMNS):
        features[column] = pd.to_numeric(features[column], errors="coerce")

    return features, labels


def build_nsl_kdd_preprocessor(features: pd.DataFrame) -> ColumnTransformer:
    categorical_columns = [
        column for column in NSL_KDD_CATEGORICAL_COLUMNS if column in features.columns
    ]
    numeric_columns = [
        column for column in features.columns if column not in categorical_columns
    ]

    numeric_pipeline = Pipeline(
        steps=[
            ("impute", SimpleImputer(strategy="median")),
            ("scale", StandardScaler()),
        ]
    )
    categorical_pipeline = Pipeline(
        steps=[
            ("impute", SimpleImputer(strategy="most_frequent")),
            ("encode", OneHotEncoder(handle_unknown="ignore")),
        ]
    )

    return ColumnTransformer(
        transformers=[
            ("numeric", numeric_pipeline, numeric_columns),
            ("categorical", categorical_pipeline, categorical_columns),
        ]
    )


def train_nsl_kdd(data_path: str, model_path: str) -> None:
    features, labels = load_nsl_kdd_dataset(data_path)

    x_train, x_test, y_train, y_test = train_test_split(
        features,
        labels,
        test_size=0.25,
        random_state=42,
        stratify=labels,
    )

    model = Pipeline(
        steps=[
            ("preprocess", build_nsl_kdd_preprocessor(features)),
            (
                "classifier",
                RandomForestClassifier(
                    n_estimators=150,
                    random_state=42,
                    class_weight="balanced",
                    n_jobs=-1,
                ),
            ),
        ]
    )
    model.fit(x_train, y_train)

    predictions = model.predict(x_test)
    print(classification_report(y_test, predictions))

    output = Path(model_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, output)
    print(f"Saved trained NSL-KDD IDS model to {output}")


def train_demo(data_path: str, model_path: str) -> None:
    dataset = load_dataset(data_path, require_labels=True)
    if dataset.labels is None:
        raise ValueError("Training requires a label column.")

    x_train, x_test, y_train, y_test = train_test_split(
        dataset.features,
        dataset.labels,
        test_size=0.25,
        random_state=42,
        stratify=dataset.labels,
    )

    model = Pipeline(
        steps=[
            ("preprocess", build_preprocessor()),
            (
                "classifier",
                RandomForestClassifier(
                    n_estimators=150,
                    random_state=42,
                    class_weight="balanced",
                ),
            ),
        ]
    )
    model.fit(x_train, y_train)

    predictions = model.predict(x_test)
    print(classification_report(y_test, predictions))

    output = Path(model_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, output)
    print(f"Saved trained IDS model to {output}")


def train(data_path: str, model_path: str, dataset_format: str = "nsl-kdd") -> None:
    if dataset_format == "nsl-kdd":
        train_nsl_kdd(data_path, model_path)
        return

    if dataset_format == "demo":
        train_demo(data_path, model_path)
        return

    try:
        train_nsl_kdd(data_path, model_path)
    except ValueError:
        train_demo(data_path, model_path)


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the intrusion detection model.")
    parser.add_argument(
        "--data",
        default=DEFAULT_NSL_KDD_DATA_PATH,
        help="Path to labeled NSL-KDD training CSV/TXT/ZIP.",
    )
    parser.add_argument("--model", default=DEFAULT_MODEL_PATH)
    parser.add_argument(
        "--format",
        choices=["auto", "demo", "nsl-kdd"],
        default="nsl-kdd",
        help="Dataset format. Defaults to nsl-kdd for KDDTrain+/KDDTest+ files.",
    )
    args = parser.parse_args()

    train(args.data, args.model, args.format)


if __name__ == "__main__":
    main()
