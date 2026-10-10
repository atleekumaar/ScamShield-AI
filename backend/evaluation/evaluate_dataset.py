"""Quantitative evaluation script measuring ScamShield AI threat detection metrics.

Computes Precision, Recall, F1-Score, Accuracy, and Confusion Matrix across
the labeled evaluation dataset.
"""

import asyncio
import json
from pathlib import Path
from typing import Dict, List, Tuple

from backend.app.models.schemas import AnalyzeRequest
from backend.app.services.llm_provider import MockLLMProvider
from backend.app.services.threat_analyzer import ThreatAnalyzer


async def run_evaluation() -> Dict[str, any]:
    dataset_path = Path(__file__).resolve().parent.parent.parent / "data" / "sample_messages.json"
    with open(dataset_path, "r", encoding="utf-8") as f:
        dataset: List[dict] = json.load(f)

    analyzer = ThreatAnalyzer(llm_provider=MockLLMProvider())

    tp = 0  # True Positive: Malicious predicted as Malicious (risk_score >= 40)
    fp = 0  # False Positive: Legitimate predicted as Malicious
    tn = 0  # True Negative: Legitimate predicted as Legitimate (risk_score < 40)
    fn = 0  # False Negative: Malicious predicted as Legitimate

    detailed_results = []

    for item in dataset:
        actual_malicious = item["expected_is_malicious"]
        report = await analyzer.analyze(AnalyzeRequest(content=item["text"]))
        predicted_malicious = report.risk_score >= 40.0

        if actual_malicious and predicted_malicious:
            tp += 1
            verdict = "TP"
        elif not actual_malicious and not predicted_malicious:
            tn += 1
            verdict = "TN"
        elif not actual_malicious and predicted_malicious:
            fp += 1
            verdict = "FP"
        else:
            fn += 1
            verdict = "FN"

        detailed_results.append({
            "id": item["id"],
            "category": item["category"],
            "expected_malicious": actual_malicious,
            "predicted_score": report.risk_score,
            "severity": report.severity.value,
            "verdict": verdict,
        })

    total = len(dataset)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / total if total > 0 else 0.0

    return {
        "dataset_size": total,
        "class_balance": {
            "malicious_samples": sum(1 for d in dataset if d["expected_is_malicious"]),
            "legitimate_samples": sum(1 for d in dataset if not d["expected_is_malicious"]),
        },
        "confusion_matrix": {
            "true_positives": tp,
            "false_positives": fp,
            "true_negatives": tn,
            "false_negatives": fn,
        },
        "metrics": {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "accuracy": round(accuracy, 4),
        },
        "detailed_results": detailed_results,
    }


if __name__ == "__main__":
    results = asyncio.run(run_evaluation())
    print("\n" + "=" * 50)
    print("SCAMSHIELD AI — QUANTITATIVE EVALUATION REPORT")
    print("=" * 50)
    print(f"Dataset Size: {results['dataset_size']} items")
    print(f"Class Balance: {results['class_balance']['malicious_samples']} Malicious / {results['class_balance']['legitimate_samples']} Legitimate")
    print("-" * 50)
    print("Confusion Matrix:")
    print(f"  True Positives (TP):  {results['confusion_matrix']['true_positives']}")
    print(f"  False Positives (FP): {results['confusion_matrix']['false_positives']}")
    print(f"  True Negatives (TN):  {results['confusion_matrix']['true_negatives']}")
    print(f"  False Negatives (FN): {results['confusion_matrix']['false_negatives']}")
    print("-" * 50)
    print(f"Accuracy:  {results['metrics']['accuracy'] * 100:.1f}%")
    print(f"Precision: {results['metrics']['precision'] * 100:.1f}%")
    print(f"Recall:    {results['metrics']['recall'] * 100:.1f}%")
    print(f"F1-Score:  {results['metrics']['f1_score']:.4f}")
    print("=" * 50)
