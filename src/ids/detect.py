from __future__ import annotations

import argparse

import joblib
import pandas as pd

from .features import load_dataset


def detect(input_path: str, model_path: str) -> pd.DataFrame:
    dataset = load_dataset(input_path, require_labels=False)
    model = joblib.load(model_path)

    results = dataset.features.copy()
    results["prediction"] = model.predict(dataset.features)

    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(dataset.features)
        classes = list(model.classes_)
        if "attack" in classes:
            attack_index = classes.index("attack")
            results["attack_probability"] = probabilities[:, attack_index]

    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Detect suspicious network traffic.")
    parser.add_argument("--input", required=True, help="Path to traffic CSV.")
    parser.add_argument("--model", default="models/ids_model.joblib")
    parser.add_argument("--output", help="Optional path to save predictions as CSV.")
    args = parser.parse_args()

    results = detect(args.input, args.model)
    print(results.to_string(index=False))

    if args.output:
        results.to_csv(args.output, index=False)
        print(f"Saved detection results to {args.output}")


if __name__ == "__main__":
    main()
